// SPDX-License-Identifier: Apache-2.0

// Package forwarder 把富化后的事件批量外送：攒批 → Ingest.Stream RPC。
// 断线期间内存暂存上限 10 批，超出落 spool；恢复后 spool 优先重放，
// 实时事件在重放期间继续落 spool 兜底。
package forwarder

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/xycxmz/xiezhi-public/proto"

	"github.com/xycxmz/xiezhi-public/agent/internal/config"
)

// Sender 是一个批次的外送动作。每批一个 Stream RPC（Send+CloseAndRecv），
// 使 accepted 能按批记日志；生产实现见 GRPCSender。
type Sender interface {
	SendBatch(ctx context.Context, batch *pb.EventBatch) (accepted uint64, err error)
}

const (
	inputChanCap  = 4096
	memBatchLimit = 10
	flushTimeout  = 10 * time.Second
	boBase        = time.Second
	boMax         = time.Minute
)

type Forwarder struct {
	in    chan *pb.Event
	sendQ chan []*pb.Event

	batchMax      int
	flushInterval time.Duration

	sender Sender
	spool  *spoolWriter
	cursor cursor // sender goroutine 独占

	sentEvents   atomic.Uint64
	spoolDropped atomic.Uint64
	runDone      chan struct{}

	// 测试注入点（包内测试可改）；0 走生产默认。
	FlushTimeout time.Duration
	BackoffBase  time.Duration
	BackoffMax   time.Duration

	// 永久性错误的退出函数（测试注入点；nil 走生产 log.Fatalf）。
	fatalf func(format string, args ...any)
}

func New(cfg *config.Config, sender Sender) (*Forwarder, error) {
	sp, err := openSpool(cfg.SpoolDir, int64(cfg.SpoolMaxMB)<<20)
	if err != nil {
		return nil, err
	}
	batchMax, flushMS := cfg.BatchMax, cfg.BatchFlushMS
	if batchMax <= 0 {
		batchMax = 100
	}
	if flushMS <= 0 {
		flushMS = 1000
	}
	return &Forwarder{
		in:            make(chan *pb.Event, inputChanCap),
		sendQ:         make(chan []*pb.Event, memBatchLimit),
		batchMax:      batchMax,
		flushInterval: time.Duration(flushMS) * time.Millisecond,
		sender:        sender,
		spool:         sp,
		runDone:       make(chan struct{}),
	}, nil
}

// In 是事件入口（容量 4096）。投递方须 select-default 非阻塞投递。
func (f *Forwarder) In() chan *pb.Event { return f.in }

// Done 在 Run 完成最终冲刷并收尾后关闭。
func (f *Forwarder) Done() <-chan struct{} { return f.runDone }

func (f *Forwarder) SpoolBytes() uint64 { return uint64(f.spool.totalBytes()) }

// Stats 暴露可观测计数：sender 确认送出的事件数、spool 写失败丢弃数。
func (f *Forwarder) Stats() (sent, spoolDropped uint64) {
	return f.sentEvents.Load(), f.spoolDropped.Load()
}

// Run 阻塞运行。ctx 取消后：抽干入口残余并冲刷既有批次，给 sender
// 一个 FlushTimeout 窗口重试；窗口内仍送不出去的活批回落 spool，
// 已在 spool 的数据原地保留（游标只在送出后推进），然后返回。
// 运行期出现永久性外送错误（认证/配置被拒）则经 log.Fatal 直接退出
// （fail-fast，systemd Restart 拉起），不走上述收尾。
func (f *Forwarder) Run(ctx context.Context) {
	defer close(f.runDone)
	defer f.spool.close()
	muxDone := make(chan struct{})
	senderDone := make(chan struct{})
	halt := make(chan struct{})
	go f.mux(ctx, muxDone)
	go f.senderLoop(halt, muxDone, senderDone)
	<-ctx.Done()
	<-muxDone
	deadline := f.FlushTimeout
	if deadline <= 0 {
		deadline = flushTimeout
	}
	time.AfterFunc(deadline, func() { close(halt) })
	<-senderDone
}

// mux 从 In 攒批（batchMax 条或 flushInterval 到期），批先进内存队列，
// 队列满则落 spool。
func (f *Forwarder) mux(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	batch := make([]*pb.Event, 0, f.batchMax)
	timer := time.NewTimer(time.Hour)
	timerActive := false
	stopTimer := func() {
		if timerActive && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerActive = false
	}
	defer timer.Stop()
	route := func() {
		if len(batch) == 0 {
			return
		}
		select {
		case f.sendQ <- batch:
		default:
			if err := f.spool.append(batch); err != nil {
				log.Printf("forwarder: spool append: %v", err)
				f.spoolDropped.Add(uint64(len(batch)))
			}
		}
		batch = make([]*pb.Event, 0, f.batchMax)
		stopTimer()
	}
	for {
		select {
		case ev := <-f.in:
			batch = append(batch, ev)
			if len(batch) >= f.batchMax {
				route()
			} else if !timerActive {
				timer.Reset(f.flushInterval)
				timerActive = true
			}
		case <-timer.C:
			timerActive = false
			route()
		case <-ctx.Done():
			// 入口停止投递（runtime 已停）：非阻塞抽干残余再冲刷。
			for {
				select {
				case ev := <-f.in:
					batch = append(batch, ev)
					if len(batch) >= f.batchMax {
						route()
					}
				default:
					route()
					return
				}
			}
		}
	}
}

// senderLoop 是唯一外送方：spool 积压优先（重放优先于实时），空转时等
// notify/sendQ；mux 退出且队列抽干即收工，否则等 halt（停机窗口到期）
// 后活批落 spool 返回。
func (f *Forwarder) senderLoop(halt <-chan struct{}, muxDone <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	sendCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-halt
		cancel()
	}()
	bo := &backoff{base: f.BackoffBase, max: f.BackoffMax}
	for {
		if f.spool.backlogLen() > 0 {
			if err := f.sendSpoolOnce(sendCtx, bo); err != nil {
				f.failFastIfPermanent(err)
				f.drainToSpool() // 停机窗口耗尽：内存队列活批同样回落 spool，不丢数
				return
			}
			continue
		}
		select {
		case b := <-f.sendQ:
			if err := f.sendWithRetry(sendCtx, b, bo); err != nil {
				f.failFastIfPermanent(err)
				f.spill(b)
				f.drainToSpool()
				return
			}
		case <-f.spool.notify:
		case <-sendCtx.Done():
			f.drainToSpool()
			return
		case <-muxDone:
			// 入口已停：内存队列与 spool 都空即可收工，不必耗满停机窗口。
			if len(f.sendQ) == 0 && f.spool.backlogLen() == 0 {
				return
			}
			select {
			case b := <-f.sendQ:
				if err := f.sendWithRetry(sendCtx, b, bo); err != nil {
					f.failFastIfPermanent(err)
					f.spill(b)
					f.drainToSpool()
					return
				}
			default:
			}
		}
	}
}

// sendSpoolOnce 重放一批 spool 数据。只有送出成功才推进游标，
// 失败/停机时数据原地保留（幂等：重开进程重放，服务端按 seq 去重）。
// 返回非 nil error 表示重放中止（永久性错误或停机窗口耗尽）。
func (f *Forwarder) sendSpoolOnce(ctx context.Context, bo *backoff) error {
	active := f.spool.activeSeg()
	evs, next, more := f.spoolNext(f.cursor, active)
	if len(evs) == 0 {
		// 撕裂尾在写入中或活跃段已读尽：等写侧 kick 或短轮询。
		if more {
			select {
			case <-f.spool.notify:
			case <-time.After(20 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		} else if f.spool.backlogLen() > 0 {
			// 磁盘已读尽而 backlog>0：enforce 删过未消费段却未回冲计数
			//（R8.4 审计 A-1），残留值会让 senderLoop 零延迟热旋转且
			// 停机挂死。读尽时真值必为 0，归零即校正。
			f.spool.resyncBacklog()
		}
		return nil
	}
	if err := f.sendWithRetry(ctx, evs, bo); err != nil {
		return err
	}
	f.spool.consume(f.cursor, next, len(evs))
	f.cursor = next
	return nil
}

// spoolNext 从游标起取最多 batchMax 条完整记录，返回事件与
// 消费后的新游标（未提交）；more 表示可能还有后继数据。
func (f *Forwarder) spoolNext(c cursor, active int64) ([]*pb.Event, cursor, bool) {
	for c.seg <= active {
		evs, end, torn, err := scanSegment(segPath(f.spool.dir, c.seg), c.off, f.batchMax)
		switch {
		case err != nil:
			if errors.Is(err, os.ErrNotExist) {
				c = cursor{c.seg + 1, 0} // 已释放/丢失的段：前进
				continue
			}
			// 不可读段（IO 故障）：跳过并大声报错；backlog 可能残留
			// 导致 20ms 空轮询，属于可见的降级状态而非静默丢数。
			log.Printf("spool: read seg %d: %v", c.seg, err)
			c = cursor{c.seg + 1, 0}
			continue
		case len(evs) > 0:
			return evs, cursor{c.seg, end}, true
		case c.seg < active:
			c = cursor{c.seg + 1, 0} // 已封口且读尽：前进
			continue
		default:
			return nil, c, torn // 活跃段读尽或撕裂
		}
	}
	return nil, c, false
}

func (f *Forwarder) spill(b []*pb.Event) {
	if err := f.spool.append(b); err != nil {
		log.Printf("forwarder: spool spill: %v", err)
		f.spoolDropped.Add(uint64(len(b)))
	}
}

// errPermanentSend 标记不可重试的外送失败（认证/配置被拒）：
// 重试不可能自愈，调用方须 fail-fast 退出交 systemd 重启。
var errPermanentSend = errors.New("permanent send failure")

// tlsErrPrefixes 是 GRPCSender 本地校验 TLS 材料的报错前缀（grpc.go
// transportCredentials）：非 gRPC 状态错误，但同属永久性配置错误
// （每次尝试必然同样失败）。同包内约定，随 grpc.go 一同变更。
var tlsErrPrefixes = []string{
	"tls config partial:",
	"load client cert:",
	"read tls_ca:",
	"tls_ca: no valid certificates",
}

// isPermanentSendErr 分类外送错误：认证/配置被拒（Unauthenticated/
// InvalidArgument/FailedPrecondition，含 TLS 材料缺项/证书错）为永久，
// 其余（网络类 Unavailable、ctx 取消等）视为瞬时。永久错误只能靠
// 运维介入（改 token/TLS、服务端恢复前置条件）解除，无限退避只会
// 队头阻塞整条外送管线直至 spool 打满（R8.4 审计 A-3）。
func isPermanentSendErr(err error) bool {
	switch status.Code(err) {
	case codes.Unauthenticated, codes.InvalidArgument, codes.FailedPrecondition:
		return true
	}
	msg := err.Error()
	for _, p := range tlsErrPrefixes {
		if strings.HasPrefix(msg, p) {
			return true
		}
	}
	return false
}

// failFastIfPermanent 对永久性外送错误 log.Fatal 退出进程：静默退避是
// 降级而非重试（数据永远送不出去，spool 终将打满），退出交 systemd
// Restart 拉起、运维修配置后重载，fail-fast 优于静默降级（与 grpc.go:34
// 既有声明同理）。水位/spool 均已落盘，重启后按 seq 幂等重放。
func (f *Forwarder) failFastIfPermanent(err error) {
	if !errors.Is(err, errPermanentSend) {
		return
	}
	fn := f.fatalf
	if fn == nil {
		fn = log.Fatalf
	}
	fn("forwarder: permanent send failure: %v (exiting for restart; check token/TLS config)", err)
}

// sendWithRetry 送一批，瞬时失败按退避重试至成功或 ctx 取消（返回
// ctx 错误）；永久性错误（认证/配置被拒）首错即返回 errPermanentSend
// 包装的终止错误，由调用方 fail-fast，不再退避空转。
func (f *Forwarder) sendWithRetry(ctx context.Context, evs []*pb.Event, bo *backoff) error {
	batch := &pb.EventBatch{Events: evs}
	for {
		accepted, err := f.sender.SendBatch(ctx, batch)
		if err == nil {
			f.sentEvents.Add(uint64(len(evs)))
			log.Printf("forwarder: sent batch of %d events, accepted=%d", len(evs), accepted)
			bo.reset()
			return nil
		}
		if isPermanentSendErr(err) {
			return fmt.Errorf("%w: %w", errPermanentSend, err)
		}
		wait := bo.next()
		log.Printf("forwarder: send failed (%v), retry in %s", err, wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// backoff 指数退避：base 起步、翻倍、max 封顶，每次 ±20% 抖动。
type backoff struct {
	base, max, cur time.Duration
}

func (b *backoff) next() time.Duration {
	if b.base <= 0 {
		b.base = boBase
	}
	if b.max <= 0 {
		b.max = boMax
	}
	if b.cur == 0 {
		b.cur = b.base
	} else {
		b.cur *= 2
		if b.cur > b.max {
			b.cur = b.max
		}
	}
	j := b.cur / 5
	return b.cur + time.Duration(rand.Int63n(int64(2*j+1))) - j
}

func (b *backoff) reset() { b.cur = 0 }

// drainToSpool 把停机窗口耗尽后滞留内存队列的批全部落盘，不丢数。
func (f *Forwarder) drainToSpool() {
	for {
		select {
		case b := <-f.sendQ:
			f.spill(b)
		default:
			return
		}
	}
}
