// SPDX-License-Identifier: Apache-2.0

package forwarder

// spool 记录格式（跨重启契约，改动需带迁移）：
//
//	段文件名  seg-%08d.seg（十进制序号单调递增，从 0 起）
//	记录      4 字节大端长度 N + N 字节 proto 序列化的 pb.Event
//	撕裂尾    长度头已落盘但负载不完整：读取端停在该记录起点，
//	          打开时截断到该边界修复（幂等：重开收敛到同一状态）。
//
// 段滚动上限 64MiB；写侧总量超过 spool_max_mb 删最旧段（活跃段——
// 当前写入段——除外）。删最旧段可能丢弃未重放数据：以磁盘有界优先
// 于完整性，服务端按 (agent_id, seq) 断链可见丢失。
//
// 所有权：append/enforce/段删除/游标推进全部经 spoolWriter.mu 串行；
// 读取（scanSegment）用独立只读句柄，靠撕裂尾容忍与写并发。
// 无 fsync：进程崩溃依赖页缓存存活，OS 崩溃丢失尾部未送事件可接受
// （spool 本就是尽力重放）。
import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

const segmentLimit int64 = 64 << 20

// cursor 是读取游标（sender goroutine 独占持有，经 consume 提交）。
type cursor struct{ seg, off int64 }

type spoolWriter struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	cur      *os.File // 当前写入段；nil = 尚未创建
	curSeg   int64
	sizes    map[int64]int64
	total    int64
	backlog  atomic.Int64 // 已追加未消费的记录数
	notify   chan struct{}
}

func segPath(dir string, seg int64) string {
	return filepath.Join(dir, fmt.Sprintf("seg-%08d.seg", seg))
}

func openSpool(dir string, maxBytes int64) (*spoolWriter, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &spoolWriter{
		dir:      dir,
		maxBytes: maxBytes,
		sizes:    map[int64]int64{},
		notify:   make(chan struct{}, 1),
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var segs []int64
	for _, e := range entries {
		n, ok := parseSegName(e.Name())
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		segs = append(segs, n)
		w.sizes[n] = info.Size()
		w.total += info.Size()
	}
	for _, s := range segs {
		n, err := w.countRecords(s)
		if err != nil {
			return nil, err
		}
		w.backlog.Add(int64(n))
	}
	if len(segs) > 0 {
		last := segs[len(segs)-1]
		w.curSeg = last
		w.repairTornTail(last)
	}
	return w, nil
}

func parseSegName(name string) (int64, bool) {
	if !strings.HasSuffix(name, ".seg") || !strings.HasPrefix(name, "seg-") {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(name, "seg-"), ".seg"), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// countRecords 统计段内完整记录数（打开路径专用，撕裂尾不计）。
func (w *spoolWriter) countRecords(seg int64) (int, error) {
	evs, _, _, err := scanSegment(segPath(w.dir, seg), 0, 1<<30)
	if err != nil {
		return 0, err
	}
	return len(evs), nil
}

func (w *spoolWriter) repairTornTail(seg int64) {
	_, end, torn, err := scanSegment(segPath(w.dir, seg), 0, 1<<30)
	if err != nil || !torn {
		return
	}
	if err := os.Truncate(segPath(w.dir, seg), end); err != nil {
		log.Printf("spool: repair truncate %s: %v", segPath(w.dir, seg), err)
		return
	}
	if sz, ok := w.sizes[seg]; ok {
		w.total -= sz - end
		w.sizes[seg] = end
	}
}

func (w *spoolWriter) append(evs []*pb.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, ev := range evs {
		payload, err := proto.Marshal(ev)
		if err != nil {
			return err
		}
		rec := make([]byte, 4+len(payload))
		binary.BigEndian.PutUint32(rec, uint32(len(payload)))
		copy(rec[4:], payload)
		if err := w.ensureCurLocked(); err != nil {
			return err
		}
		if w.sizes[w.curSeg]+int64(len(rec)) > segmentLimit && w.sizes[w.curSeg] > 0 {
			if err := w.rollLocked(); err != nil {
				return err
			}
		}
		if _, err := w.cur.Write(rec); err != nil {
			return err
		}
		w.sizes[w.curSeg] += int64(len(rec))
		w.total += int64(len(rec))
		// 逐记录累计：写一半失败时已落盘记录仍会被重放。
		w.backlog.Add(1)
	}
	w.enforceLocked()
	w.kick()
	return nil
}

func (w *spoolWriter) ensureCurLocked() error {
	if w.cur != nil {
		return nil
	}
	f, err := os.OpenFile(segPath(w.dir, w.curSeg), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, ok := w.sizes[w.curSeg]; !ok {
		w.sizes[w.curSeg] = 0
	}
	w.cur = f
	return nil
}

func (w *spoolWriter) rollLocked() error {
	if w.cur != nil {
		if err := w.cur.Close(); err != nil {
			return err
		}
		w.cur = nil
	}
	w.curSeg++
	w.sizes[w.curSeg] = 0
	return w.ensureCurLocked()
}

// enforceLocked 删最旧段直到总量回到预算内。活跃段不删（正在写），
// 只剩活跃段时容忍超额，下次滚动自然回收。
func (w *spoolWriter) enforceLocked() {
	for w.total > w.maxBytes {
		oldest := int64(-1)
		for s := range w.sizes {
			if s < w.curSeg && (oldest < 0 || s < oldest) {
				oldest = s
			}
		}
		if oldest < 0 {
			return
		}
		w.removeSegLocked(oldest)
	}
}

func (w *spoolWriter) removeSegLocked(seg int64) {
	if err := os.Remove(segPath(w.dir, seg)); err != nil && !os.IsNotExist(err) {
		log.Printf("spool: remove %s: %v", segPath(w.dir, seg), err)
		return
	}
	w.total -= w.sizes[seg]
	delete(w.sizes, seg)
}

// consume 提交游标推进：释放途经的已封口段；若活跃段被完整消费且
// 无积压，删除它并滚动到新段，让 SpoolBytes 归零。
func (w *spoolWriter) consume(old, next cursor, n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.backlog.Add(int64(-n))
	for s := old.seg; s < next.seg; s++ {
		w.removeSegLocked(s)
	}
	if w.backlog.Load() == 0 && next.seg == w.curSeg && w.sizes[w.curSeg] > 0 && next.off >= w.sizes[w.curSeg] {
		if w.cur != nil {
			_ = w.cur.Close()
			w.cur = nil
		}
		w.removeSegLocked(w.curSeg)
		w.curSeg++
		w.sizes[w.curSeg] = 0
	}
	w.kick()
}

func (w *spoolWriter) activeSeg() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.curSeg
}

func (w *spoolWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur != nil {
		_ = w.cur.Close()
		w.cur = nil
	}
}

func (w *spoolWriter) totalBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.total
}

func (w *spoolWriter) backlogLen() int64 { return w.backlog.Load() }

// resyncBacklog 读尽场景的 backlog 自校正（A-1）：磁盘无可读数据时真值
// 必为 0；enforce 删未消费段不回冲计数会留下假正值。
func (w *spoolWriter) resyncBacklog() { w.backlog.Store(0) }

func (w *spoolWriter) kick() {
	select {
	case w.notify <- struct{}{}:
	default:
	}
}

// scanSegment 从 off 起读最多 max 条完整记录。
// 返回事件、扫描终点、是否因撕裂/损坏提前停；文件缺失时 err 为
// fs.ErrNotExist。
func scanSegment(path string, off int64, max int) (evs []*pb.Event, end int64, torn bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, off, false, err
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, off, false, err
	}
	r := bufio.NewReader(f)
	end = off
	for len(evs) < max {
		var hdr [4]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.EOF {
				return evs, end, false, nil // 干净到尾
			}
			return evs, end, true, nil // 半个长度头：撕裂
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if int64(n) > segmentLimit {
			// 长度头是磁盘上的不可信值（崩溃/损坏可产出任意垃圾，最高 4GiB）：
			// 超界记录按撕裂停在起点，不按 n 分配内存。
			return evs, end, true, nil
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return evs, end, true, nil // 负载不完整：撕裂
		}
		ev := &pb.Event{}
		if err := proto.Unmarshal(payload, ev); err != nil {
			return evs, end, true, nil // 损坏记录当撕裂处理
		}
		evs = append(evs, ev)
		end += 4 + int64(n)
	}
	return evs, end, false, nil
}
