// SPDX-License-Identifier: Apache-2.0

//go:build linux

package journal

import (
	"bytes"
	"io"
	"os"
	"syscall"
)

const (
	// startWindow 是初始定位 -N 行时回看的字节窗口（auth 行均长 ~100B，
	// 64KB 覆盖百行量级绰绰有余）。
	startWindow = 64 * 1024
	// maxLine 是单行上界：无换行的超长垃圾不得无限吃内存，超限整块当
	// 一行交出去（几乎必然解析失败被计跳过）。
	maxLine = 64 * 1024
)

// tailer 是文件 tail 状态机，(inode, offset) 是对轮转的全部判断依据：
// inode 变化（logrotate rename+create）或 size < offset（copytruncate）
// 都重开从 0；路径暂时消失（轮转间隙）保留状态下轮重试。
// 读位置不变式：fd 位置 = offset + len(pending)，offset 只跨完整行推进。
type tailer struct {
	path        string
	file        *os.File
	inode       uint64
	offset      int64
	startLines  int
	initialDone bool
	pending     []byte // 已读未完结的半行
	readBuf     []byte
}

func newTailer(path string, startLines int) *tailer {
	return &tailer{path: path, startLines: startLines, readBuf: make([]byte, 32*1024)}
}

func (t *tailer) closeFile() {
	if t.file != nil {
		t.file.Close()
		t.file = nil
	}
	// 旧文件的半行与轮转后的新内容无关
	t.pending = t.pending[:0]
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// open 打开文件。fromStart=false（采集器初次启动）时把读取位置定位到
// 「倒数第 startLines 个完整行」的行首（tail -N 语义：起点后的行都投递，
// 历史不洪水）；fromStart=true（轮转重开）从 0 读新文件。
func (t *tailer) open(fromStart bool) error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	t.file = f
	t.inode = inodeOf(fi)
	t.pending = t.pending[:0]

	var start int64
	if !fromStart {
		if size := fi.Size(); size > startWindow {
			start = size - startWindow
		}
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		t.closeFile()
		return err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		t.closeFile()
		return err
	}
	if start > 0 {
		// 窗口首行大概率被劈开，丢弃到下一个换行
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	t.offset = start
	t.pending = append(t.pending, data...)
	return nil
}

// poll 走一轮：处理轮转/截断，把新到的完整行吐出来。路径消失返回空批
// （调用方下轮重试），只有不可恢复的错误才返回 err。
func (t *tailer) poll() ([]string, error) {
	if t.file == nil {
		// 首次启动走 tail -N 定位；路径消失后的重开与 inode 轮转路径同义，
		// 必须从 0 读，否则替换文件在间隙期写超 startWindow 的前段行被跳过。
		if err := t.open(t.initialDone); err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
	} else {
		fi, err := os.Stat(t.path)
		switch {
		case os.IsNotExist(err):
			// rename+create 的间隙或文件被删：下轮重开
			t.closeFile()
			return nil, nil
		case err != nil:
			return nil, err
		case inodeOf(fi) != t.inode:
			// 轮转出新文件（新 inode）：重开从 0
			t.closeFile()
			if err := t.open(true); err != nil {
				if os.IsNotExist(err) {
					return nil, nil
				}
				return nil, err
			}
		case fi.Size() < t.offset:
			// copytruncate：同 inode 原地截短，从 0 重读
			t.offset = 0
			t.pending = t.pending[:0]
			if _, err := t.file.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
		}
	}

	for {
		n, err := t.file.Read(t.readBuf)
		if n > 0 {
			t.pending = append(t.pending, t.readBuf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return t.drain(), nil
}

// drain 从 pending 里切出完整行并推进 offset；无换行但超 maxLine 的块按
// 一行强制吐出。首轮超过 startLines 条时只保留最后 startLines 条（历史
// 窗口外的丢弃不投递）。
func (t *tailer) drain() []string {
	var lines []string
	for len(t.pending) > 0 {
		i := bytes.IndexByte(t.pending, '\n')
		if i < 0 {
			if len(t.pending) < maxLine {
				break
			}
			lines = append(lines, string(t.pending))
			t.offset += int64(len(t.pending))
			t.pending = t.pending[:0]
			break
		}
		lines = append(lines, string(t.pending[:i]))
		t.pending = t.pending[i+1:]
		t.offset += int64(i + 1)
	}
	if !t.initialDone {
		t.initialDone = true
		if len(lines) > t.startLines {
			lines = lines[len(lines)-t.startLines:]
		}
	}
	return lines
}

// close 由 Collector.Close 调用。
func (t *tailer) close() { t.closeFile() }
