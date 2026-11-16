// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procpoll

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procEntry 是一次 /proc 扫描里的一条进程身份。(pid, start_ticks) 复合键防
// PID 复用（与 proto ProcessContext.start_ticks 同一口径）。
type procEntry struct {
	Pid        uint32
	Comm       string
	Ppid       uint32
	StartTicks uint64
	Exe        string // readlink /proc/<pid>/exe，失败留空（内核线程/权限/僵尸）
}

// snapshot 是一轮扫描的进程全集，pid 为键。
type snapshot map[uint32]procEntry

// scan 遍历 root（生产为 /proc，测试注入假目录树）下所有 [0-9]+ 目录，
// 汇成快照。单个进程在扫描瞬间退出（status/stat 读失败或解析失败）只跳过
// 该 pid，不失败整轮——下轮它会以 appeared 回来，属可接受噪声。
func scan(root string) snapshot {
	dirs, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	snap := make(snapshot, len(dirs))
	for _, d := range dirs {
		pid, err := strconv.ParseUint(d.Name(), 10, 32)
		if err != nil || !d.IsDir() {
			continue
		}
		e, ok := readProcEntry(filepath.Join(root, d.Name()), uint32(pid))
		if ok {
			snap[uint32(pid)] = e
		}
	}
	return snap
}

func readProcEntry(procDir string, pid uint32) (procEntry, bool) {
	comm, ppid, ok := readStatus(filepath.Join(procDir, "status"))
	if !ok {
		return procEntry{}, false
	}
	ticks, ok := readStartTicks(filepath.Join(procDir, "stat"))
	if !ok {
		return procEntry{}, false
	}
	// exe 失败容忍：内核线程无 exe、其他用户进程读 link 需 ptrace 权限
	exe, _ := os.Readlink(filepath.Join(procDir, "exe"))
	// comm 可经 prctl 设任意字节、exe 路径可含非 UTF-8，进 proto string 前洗
	return procEntry{
		Pid:        pid,
		Comm:       strings.ToValidUTF8(comm, "\uFFFD"),
		Ppid:       ppid,
		StartTicks: ticks,
		Exe:        strings.ToValidUTF8(exe, "\uFFFD"),
	}, true
}

// readStatus 取 Name 与 PPid 两行。status 里 comm 也是 15 字符截断，
// 但带转义（\t 等）时仍是内核原文的最好近似。
func readStatus(path string) (comm string, ppid uint32, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "Name:"):
			comm = strings.TrimSpace(line[len("Name:"):])
		case strings.HasPrefix(line, "PPid:"):
			v, err := strconv.ParseUint(strings.TrimSpace(line[len("PPid:"):]), 10, 32)
			if err != nil {
				return "", 0, false
			}
			ppid = uint32(v)
		}
	}
	return comm, ppid, comm != ""
}

// readStartTicks 取 /proc/<pid>/stat 字段 22（starttime，时钟 tick）。
// comm（字段 2）可含空格与括号，必须按最后一个 ')' 切，其后才是字段 3 起。
func readStartTicks(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := string(b)
	end := strings.LastIndexByte(s, ')')
	if end < 0 {
		return 0, false
	}
	fields := strings.Fields(s[end+1:])
	// fields[0] = 字段 3（state），starttime 是字段 22 → 下标 22-3 = 19
	if len(fields) < 20 {
		return 0, false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return ticks, true
}

// diffAppeared 返回本轮相对上轮新出现的进程 pid。同 pid 但 start_ticks 变化
// 视为旧进程退出+新进程复用该 pid，按 appeared 上报（M3 会话层与内核事件流
// 对账时凭 start_ticks 区分）。返回按 pid 数值序排序，保证事件内容确定。
func diffAppeared(prev, cur snapshot) []uint32 {
	var appeared []uint32
	for pid, e := range cur {
		old, seen := prev[pid]
		if !seen || old.StartTicks != e.StartTicks {
			appeared = append(appeared, pid)
		}
	}
	for i := 1; i < len(appeared); i++ {
		for j := i; j > 0 && appeared[j] < appeared[j-1]; j-- {
			appeared[j], appeared[j-1] = appeared[j-1], appeared[j]
		}
	}
	return appeared
}
