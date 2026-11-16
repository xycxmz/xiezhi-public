// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"encoding/binary"
	"os"
	"testing"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

func mkEvent(seq uint64) *pb.Event {
	return &pb.Event{Header: &pb.EventHeader{Seq: seq}}
}

func TestSpoolAppendReplayRoundtrip(t *testing.T) {
	dir := t.TempDir()
	w, err := openSpool(dir, 64<<20)
	if err != nil {
		t.Fatalf("openSpool: %v", err)
	}
	defer w.close()
	var batch []*pb.Event
	for i := uint64(1); i <= 5; i++ {
		batch = append(batch, mkEvent(i))
	}
	if err := w.append(batch); err != nil {
		t.Fatalf("append: %v", err)
	}
	if got := w.backlogLen(); got != 5 {
		t.Fatalf("backlog = %d, want 5", got)
	}

	f := &Forwarder{spool: w, batchMax: 3}
	active := w.activeSeg()

	evs, next, _ := f.spoolNext(cursor{}, active)
	if len(evs) != 3 || evs[0].Header.Seq != 1 || evs[2].Header.Seq != 3 {
		t.Fatalf("first read = %d events (seq %v), want 3 events seq 1..3", len(evs), seqs(evs))
	}
	w.consume(cursor{}, next, len(evs))
	f.cursor = next

	evs, next, more := f.spoolNext(f.cursor, active)
	if len(evs) != 2 || evs[0].Header.Seq != 4 || evs[1].Header.Seq != 5 {
		t.Fatalf("second read = %d events (seq %v), want 2 events seq 4..5", len(evs), seqs(evs))
	}
	w.consume(f.cursor, next, len(evs))
	f.cursor = next

	if evs, _, more = f.spoolNext(f.cursor, w.activeSeg()); len(evs) != 0 || more {
		t.Fatalf("drained spool returned %d events more=%v, want none", len(evs), more)
	}
	if got := w.backlogLen(); got != 0 {
		t.Fatalf("backlog after drain = %d, want 0", got)
	}
	if got := w.totalBytes(); got != 0 {
		t.Fatalf("spool bytes after drain = %d, want 0 (active segment recycled)", got)
	}
}

func TestSpoolTornTailRepairedOnOpen(t *testing.T) {
	dir := t.TempDir()
	w, err := openSpool(dir, 64<<20)
	if err != nil {
		t.Fatalf("openSpool: %v", err)
	}
	if err := w.append([]*pb.Event{mkEvent(1), mkEvent(2), mkEvent(3)}); err != nil {
		t.Fatal(err)
	}
	w.close()
	path := segPath(dir, 0)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 100)
	if _, err := f.Write(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	f.Close()

	w2, err := openSpool(dir, 64<<20)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.close()
	if got := w2.backlogLen(); got != 3 {
		t.Fatalf("backlog after repair = %d, want 3 (torn record dropped)", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	scan := func() int64 {
		_, end, _, err := scanSegment(path, 0, 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		return end
	}
	if info.Size() != scan() {
		t.Fatalf("file size %d != last complete record end %d (torn tail not truncated)", info.Size(), scan())
	}
}

// 越界长度头（磁盘不可信值，最高 4GiB）：scanSegment 停在该记录起点按撕裂
// 处理、不按 n 分配内存；openSpool 的修复截断把它清掉，启动不崩。
func TestSpoolBogusLengthHeaderTreatedAsTorn(t *testing.T) {
	dir := t.TempDir()
	w, err := openSpool(dir, 64<<20)
	if err != nil {
		t.Fatalf("openSpool: %v", err)
	}
	if err := w.append([]*pb.Event{mkEvent(1), mkEvent(2)}); err != nil {
		t.Fatal(err)
	}
	w.close()
	path := segPath(dir, 0)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 0xFFFFFFFF)
	if _, err := f.Write(hdr); err != nil {
		t.Fatal(err)
	}
	f.Close()

	evs, end, torn, err := scanSegment(path, 0, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || !torn {
		t.Fatalf("scan = %d events torn=%v, want 2 events torn=true (stop before bogus header)", len(evs), torn)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Size() != end+4 {
		t.Fatalf("file size %d, scan end %d (bogus header must be the trailing 4 bytes)", info.Size(), end)
	}

	w2, err := openSpool(dir, 64<<20)
	if err != nil {
		t.Fatalf("reopen with bogus tail: %v", err)
	}
	defer w2.close()
	if got := w2.backlogLen(); got != 2 {
		t.Fatalf("backlog after open = %d, want 2 (bogus tail truncated away)", got)
	}
}

func TestSpoolEnforceDeletesOldestSegment(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// 预置一段旧数据，让下次 append 超预算触发删最旧段。
	oldest := segPath(dir, 0)
	oldRec := make([]byte, 4+8)
	binary.BigEndian.PutUint32(oldRec, 8)
	if err := os.WriteFile(oldest, oldRec, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segPath(dir, 1), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := openSpool(dir, int64(len(oldRec))) // 预算只容旧段：新记录追加即超预算
	if err != nil {
		t.Fatalf("openSpool: %v", err)
	}
	defer w.close()
	if err := w.append([]*pb.Event{mkEvent(1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldest); !os.IsNotExist(err) {
		t.Fatalf("oldest segment still present after enforce: %v", err)
	}
	if got := w.totalBytes(); got > w.maxBytes {
		t.Fatalf("total %d exceeds budget %d", got, w.maxBytes)
	}
}

func seqs(evs []*pb.Event) []uint64 {
	out := make([]uint64, len(evs))
	for i, ev := range evs {
		out[i] = ev.Header.Seq
	}
	return out
}
