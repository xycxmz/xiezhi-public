// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/xycxmz/xiezhi-public/proto"

	"github.com/xycxmz/xiezhi-public/agent/internal/config"
)

// fakeSender 可编程：gate 阻塞调用直至放行；failN 让前 N 次尝试失败，
// failWith 指定失败返回的错误（须在启动前设置；nil 则用普通错误）。
type fakeSender struct {
	gate     chan struct{}
	entered  atomic.Int64
	failN    atomic.Int64
	failWith error
	attempts atomic.Int64
	mu       sync.Mutex
	seqsGot  []uint64
	batches  []int
}

func (s *fakeSender) SendBatch(ctx context.Context, b *pb.EventBatch) (uint64, error) {
	s.entered.Add(1)
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if s.attempts.Add(1) <= s.failN.Load() {
		if s.failWith != nil {
			return 0, s.failWith
		}
		return 0, errors.New("down")
	}
	s.mu.Lock()
	s.batches = append(s.batches, len(b.Events))
	for _, ev := range b.Events {
		s.seqsGot = append(s.seqsGot, ev.Header.Seq)
	}
	s.mu.Unlock()
	return uint64(len(b.Events)), nil
}

func (s *fakeSender) snapshot() (seqs []uint64, sizes []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.seqsGot...), append([]int(nil), s.batches...)
}

func testCfg(t *testing.T, batchMax, flushMS int) *config.Config {
	t.Helper()
	return &config.Config{
		SpoolDir:     t.TempDir(),
		SpoolMaxMB:   4,
		BatchMax:     batchMax,
		BatchFlushMS: flushMS,
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}

func runForwarder(t *testing.T, f *Forwarder) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go f.Run(ctx)
	return cancel, f.Done()
}

func TestBatchFlushedBySize(t *testing.T) {
	fs := &fakeSender{}
	f, err := New(testCfg(t, 2, 60_000), fs)
	if err != nil {
		t.Fatal(err)
	}
	f.BackoffBase = time.Millisecond
	cancel, done := runForwarder(t, f)

	f.In() <- mkEvent(1)
	f.In() <- mkEvent(2)
	f.In() <- mkEvent(3)
	f.In() <- mkEvent(4)
	waitFor(t, 2*time.Second, func() bool {
		_, sizes := fs.snapshot()
		return len(sizes) == 2
	})
	seqs, sizes := fs.snapshot()
	if len(sizes) != 2 || sizes[0] != 2 || sizes[1] != 2 {
		t.Fatalf("batch sizes = %v, want [2 2]", sizes)
	}
	if seqs[0] != 1 || seqs[1] != 2 || seqs[2] != 3 || seqs[3] != 4 {
		t.Fatalf("event order = %v, want [1 2 3 4]", seqs)
	}
	cancel()
	<-done
}

func TestBatchFlushedByTimer(t *testing.T) {
	fs := &fakeSender{}
	f, err := New(testCfg(t, 100, 30), fs)
	if err != nil {
		t.Fatal(err)
	}
	f.BackoffBase = time.Millisecond
	cancel, done := runForwarder(t, f)

	f.In() <- mkEvent(7)
	waitFor(t, 2*time.Second, func() bool {
		_, sizes := fs.snapshot()
		return len(sizes) == 1
	})
	seqs, sizes := fs.snapshot()
	if len(sizes) != 1 || sizes[0] != 1 || len(seqs) != 1 || seqs[0] != 7 {
		t.Fatalf("timer flush got sizes=%v seqs=%v, want single batch [7]", sizes, seqs)
	}
	cancel()
	<-done
}

// 断线期间的确定性画像：spool 预置 1 条标记事件，sender 开局即卡在
// 它的重放发送上（gate），期间 mux 把 10 批积满内存队列、其余落 spool
// （sender 全程不取内存队列，队列成分因此冻结为连续前缀）。放行后：
// 标记 → spool 重放 11..41 → 内存队列 1..10。重放优先 + 无丢失可精确断言。
func TestOutageSpillsAndReplayTakesPriority(t *testing.T) {
	fs := &fakeSender{gate: make(chan struct{})}
	f, err := New(testCfg(t, 1, 1), fs) // batchMax=1：每事件一批
	if err != nil {
		t.Fatal(err)
	}
	f.BackoffBase = 2 * time.Millisecond
	if err := f.spool.append([]*pb.Event{mkEvent(99)}); err != nil {
		t.Fatal(err)
	}
	cancel, done := runForwarder(t, f)

	const n = 41
	for i := uint64(1); i <= n; i++ {
		f.In() <- mkEvent(i)
	}
	waitFor(t, 2*time.Second, func() bool {
		return fs.entered.Load() == 1 && len(f.sendQ) == memBatchLimit &&
			f.spool.backlogLen() == int64(n-memBatchLimit+1) // 11..41 加未消费的标记
	})
	close(fs.gate)
	waitFor(t, 5*time.Second, func() bool {
		seqs, _ := fs.snapshot()
		return len(seqs) == n+1
	})

	want := []uint64{99}
	for i := 11; i <= n; i++ {
		want = append(want, uint64(i))
	}
	for i := uint64(1); i <= memBatchLimit; i++ {
		want = append(want, i)
	}
	got, _ := fs.snapshot()
	if len(got) != len(want) {
		t.Fatalf("received %d events, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delivery order diverges at %d: got %v..., want %v...", i, got[:i+1], want[:i+1])
		}
	}
	cancel()
	<-done
	if got := f.spool.backlogLen(); got != 0 {
		t.Fatalf("spool backlog after replay = %d, want 0", got)
	}
	if got := f.SpoolBytes(); got != 0 {
		t.Fatalf("spool bytes after replay = %d, want 0", got)
	}
}

// 停机窗口耗尽仍未送达：活批与内存队列全部回落 spool，不丢数。
func TestShutdownSpillsUnsentToSpool(t *testing.T) {
	fs := &fakeSender{gate: make(chan struct{})} // 永不放行：所有尝试阻塞到 ctx 取消
	f, err := New(testCfg(t, 10, 5), fs)
	if err != nil {
		t.Fatal(err)
	}
	f.BackoffBase = time.Millisecond
	f.FlushTimeout = 150 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go f.Run(ctx)

	f.In() <- mkEvent(1)
	f.In() <- mkEvent(2)
	f.In() <- mkEvent(3)
	waitFor(t, 2*time.Second, func() bool { return fs.entered.Load() == 1 })

	cancel()
	done := make(chan struct{})
	go func() { <-f.Done(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after shutdown window")
	}
	if got := f.spool.backlogLen(); got != 3 {
		t.Fatalf("spool backlog after shutdown = %d, want 3", got)
	}
	if seqs, _ := fs.snapshot(); len(seqs) != 0 {
		t.Fatalf("sender delivered %v despite blocked gate", seqs)
	}
}

// 停机窗口在 spool 积压重放中耗尽：内存队列的活批同样回落 spool，不丢数
// （回归：spool 积压分支曾是唯一不落盘的退出路径，10 批活批被静默丢弃）。
func TestShutdownDuringSpoolBacklogDrainsSendQ(t *testing.T) {
	fs := &fakeSender{gate: make(chan struct{})} // 永不放行：重放卡在 SendBatch
	f, err := New(testCfg(t, 1, 1), fs)
	if err != nil {
		t.Fatal(err)
	}
	f.BackoffBase = time.Millisecond
	f.FlushTimeout = 100 * time.Millisecond
	if err := f.spool.append([]*pb.Event{mkEvent(99)}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go f.Run(ctx)

	for i := uint64(1); i <= memBatchLimit; i++ {
		f.In() <- mkEvent(i)
	}
	waitFor(t, 2*time.Second, func() bool {
		return fs.entered.Load() == 1 && len(f.sendQ) == memBatchLimit
	})

	cancel()
	select {
	case <-f.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after shutdown window")
	}
	if got := f.spool.backlogLen(); got != int64(memBatchLimit+1) {
		t.Fatalf("spool backlog after shutdown = %d, want %d (live batches + marker)", got, memBatchLimit+1)
	}
	if seqs, _ := fs.snapshot(); len(seqs) != 0 {
		t.Fatalf("sender delivered %v despite blocked gate", seqs)
	}
}

// 断线重试后恢复：spool 与内存队列全部送出，无丢失无重复。
func TestRecoverAfterFailuresDeliversAll(t *testing.T) {
	fs := &fakeSender{}
	fs.failN.Store(3)
	f, err := New(testCfg(t, 5, 2), fs)
	if err != nil {
		t.Fatal(err)
	}
	f.BackoffBase = time.Millisecond
	cancel, done := runForwarder(t, f)

	const n = 40
	for i := uint64(1); i <= n; i++ {
		f.In() <- mkEvent(i)
	}
	waitFor(t, 5*time.Second, func() bool {
		seqs, _ := fs.snapshot()
		return len(seqs) == n
	})
	got, _ := fs.snapshot()
	seen := map[uint64]bool{}
	for _, s := range got {
		if seen[s] {
			t.Fatalf("duplicate seq %d delivered", s)
		}
		seen[s] = true
	}
	for i := uint64(1); i <= n; i++ {
		if !seen[i] {
			t.Fatalf("seq %d never delivered", i)
		}
	}
	cancel()
	<-done
}

// 错误分类：认证/配置类 gRPC 状态码与 TLS 材料本地校验错误为永久；
// 网络类（Unavailable）、超时与普通错误为瞬时（回归保护：分类不得
// 误杀瞬时错误，否则断线即崩溃）。
func TestIsPermanentSendErr(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad token"), true},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad batch"), true},
		{"failed precondition", status.Error(codes.FailedPrecondition, "server not ready"), true},
		{"wrapped status", fmt.Errorf("stream: %w", status.Error(codes.Unauthenticated, "bad token")), true},
		{"tls partial", errors.New("tls config partial: need all of tls_ca/tls_cert/tls_key"), true},
		{"tls bad cert", errors.New("load client cert: tls: failed to find any PEM data"), true},
		{"tls ca missing", errors.New("read tls_ca: open /etc/xiezhi/ca.pem: no such file"), true},
		{"tls ca invalid", errors.New("tls_ca: no valid certificates"), true},
		{"unavailable is transient", status.Error(codes.Unavailable, "connection refused"), false},
		{"deadline is transient", context.DeadlineExceeded, false},
		{"plain error is transient", errors.New("down"), false},
	} {
		if got := isPermanentSendErr(tc.err); got != tc.want {
			t.Errorf("%s: isPermanentSendErr = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// 永久性错误首错即终止：不退避不重试，返回可识别的 errPermanentSend。
func TestSendWithRetryPermanentErrorNoRetry(t *testing.T) {
	fs := &fakeSender{failWith: status.Error(codes.Unauthenticated, "token rejected")}
	fs.failN.Store(1 << 30) // 每次尝试都失败
	f, err := New(testCfg(t, 1, 60_000), fs)
	if err != nil {
		t.Fatal(err)
	}
	// 退避取 1 小时：若误判为瞬时，测试将超时失败而非空转重试。
	err = f.sendWithRetry(context.Background(), []*pb.Event{mkEvent(1)}, &backoff{base: time.Hour, max: time.Hour})
	if !errors.Is(err, errPermanentSend) {
		t.Fatalf("sendWithRetry err = %v, want errPermanentSend", err)
	}
	if got := fs.attempts.Load(); got != 1 {
		t.Fatalf("sender attempts = %d, want 1 (permanent error must not be retried)", got)
	}
}

// 瞬时错误仍按退避重试至成功：分类不得把网络类错误升级成终止。
func TestSendWithRetryTransientErrorStillRetried(t *testing.T) {
	fs := &fakeSender{}
	fs.failN.Store(2) // 前 2 次普通错误，第 3 次成功
	f, err := New(testCfg(t, 1, 60_000), fs)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.sendWithRetry(context.Background(), []*pb.Event{mkEvent(1)}, &backoff{base: time.Millisecond, max: time.Millisecond}); err != nil {
		t.Fatalf("sendWithRetry = %v, want nil", err)
	}
	if got := fs.attempts.Load(); got != 3 {
		t.Fatalf("sender attempts = %d, want 3 (transient error must be retried)", got)
	}
}

// senderLoop 收到终止错误即 fail-fast：注入 fatal 替身断言退出被触发，
// 不进入退避等待（BackoffBase=1h，若误退避测试超时失败）。
func TestSenderLoopFatalOnPermanentError(t *testing.T) {
	fs := &fakeSender{failWith: status.Error(codes.InvalidArgument, "rejected")}
	fs.failN.Store(1 << 30) // 每次尝试都失败
	f, err := New(testCfg(t, 1, 1), fs)
	if err != nil {
		t.Fatal(err)
	}
	f.BackoffBase = time.Hour
	fatalCalled := make(chan struct{})
	f.fatalf = func(format string, args ...any) { close(fatalCalled) }
	cancel, done := runForwarder(t, f)

	f.In() <- mkEvent(1)
	select {
	case <-fatalCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("senderLoop did not fail fast on permanent send error")
	}
	cancel()
	<-done
}
