// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lkm

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	koPrefix    = "xiezhi_driver-"
	moduleName  = "xiezhi_driver" // .ko 文件重命名不改变模块内部名（kbuild 时已定）
	crashWindow = 5 * time.Minute
	backoffBase = 1 * time.Second
	backoffMax  = 3600 * time.Second
	procWait    = 5 * time.Second
)

// koPathFor 按内核版本精确匹配 xiezhi_driver-<release>.ko（版本锁：不猜相近
// 版本，不匹配即返回明确错误，调用方降级心跳模式）。
func koPathFor(dir, release string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("lkm: driver ko dir not configured")
	}
	p := filepath.Join(dir, koPrefix+release+".ko")
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("lkm: no driver for kernel %s (want %s), agent falls back to heartbeat mode", release, p)
		}
		return "", fmt.Errorf("lkm: stat %s: %w", p, err)
	}
	return p, nil
}

// backoffDelay 返回第 failures 次（0 起）连续失败后的重试等待：1s 指数翻倍，
// 上限 3600s。
func backoffDelay(failures int) time.Duration {
	if failures < 0 {
		failures = 0
	}
	if failures >= 12 { // 1<<12s 已超上限
		return backoffMax
	}
	if d := backoffBase << failures; d > 0 && d < backoffMax {
		return d
	}
	return backoffMax
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func kernelRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// crashCheck 实现 Elkeid 式崩溃退避：insmod 前扫 dmesg 近 crashWindow 内
// 牵连 xiezhi 的 oops/BUG/panic/RIP 行，命中则拒载。dmesg 或 /proc/uptime 读取
// 失败不阻塞加载，只记日志。
func crashCheck(log *slog.Logger) error {
	out, err := runCmd("dmesg")
	if err != nil {
		log.Warn("dmesg unreadable, skipping crash backoff check", "err", err)
		return nil
	}
	boot, ok := bootTime()
	if !ok {
		log.Warn("/proc/uptime unreadable, skipping crash backoff check")
		return nil
	}
	if recentXiezhiCrash(out, boot, time.Now()) {
		return fmt.Errorf("kernel oops/BUG/panic implicating xiezhi within %s, refusing to load (Elkeid-style backoff)", crashWindow)
	}
	return nil
}

// recentXiezhiCrash 判定 dmesg 文本（uptime 时间戳格式，el7 默认）里是否有
// crashWindow 内牵连本驱动的崩溃。真实 oops 是多行分列的：崩溃标记行
//（"Oops: 0000"/"RIP: 0010:内核符号"）常不含模块名，模块名只出现在
// Call Trace / "Modules linked in" 行——按行号邻近配对判定（R8.4 审计
// A-2），同行命中只是特例。
func recentXiezhiCrash(text string, boot, now time.Time) bool {
	cutoff := now.Add(-crashWindow)
	lines := strings.Split(text, "\n")
	var xiezhiAt, markerAt []int
	for i, line := range lines {
		secs, ok := dmesgStamp(line)
		if !ok {
			continue
		}
		if boot.Add(time.Duration(secs) * time.Second).Before(cutoff) {
			continue
		}
		l := strings.ToLower(line)
		hasXZ := strings.Contains(l, "xiezhi")
		hasMarker := strings.Contains(l, "oops") || strings.Contains(l, "bug:") ||
			strings.Contains(l, "panic") || strings.Contains(l, "rip:") ||
			strings.Contains(l, "call trace")
		if hasXZ && hasMarker {
			return true
		}
		if hasXZ {
			xiezhiAt = append(xiezhiAt, i)
		}
		if hasMarker {
			markerAt = append(markerAt, i)
		}
	}
	// 邻近窗：同一次 oops 的 Call Trace 与标记行相距通常 <10 行。
	const proximity = 10
	for _, x := range xiezhiAt {
		for _, m := range markerAt {
			if x > m-proximity && x < m+proximity {
				return true
			}
		}
	}
	return false
}

// dmesgStamp 解析 "[ 86940.123456] ..." 行首的 uptime 秒数。
func dmesgStamp(line string) (int64, bool) {
	rest, ok := strings.CutPrefix(line, "[")
	if !ok {
		return 0, false
	}
	stamp, _, ok := strings.Cut(rest, "]")
	if !ok {
		return 0, false
	}
	whole, _, ok := strings.Cut(stamp, ".")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(whole), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// bootTime 由 /proc/uptime 推算启动时刻（dmesg uptime 戳换算墙上钟用）。
func bootTime() (time.Time, bool) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, false
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return time.Time{}, false
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || secs < 0 {
		return time.Time{}, false
	}
	return time.Now().Add(-time.Duration(secs * float64(time.Second))), true
}

// manager 拥有驱动加载生命周期与退避状态。ensureLoaded 幂等收敛：任一步
// 失败后状态回到未加载（部分成功时 rmmod），重试到达同一终态。
type manager struct {
	koPath   string
	log      *slog.Logger
	attempts int
	loaded   bool
}

func newManager(koDir, release string, log *slog.Logger) (*manager, error) {
	ko, err := koPathFor(koDir, release)
	if err != nil {
		return nil, err
	}
	return &manager{koPath: ko, log: log}, nil
}

// ensureLoaded 尝试一次完整加载（崩溃退避检查 → insmod → 等 /proc 出现）。
// 失败时返回建议的重试等待时长；成功后清零退避。
func (m *manager) ensureLoaded(ctx context.Context) (time.Duration, error) {
	fail := func(err error) (time.Duration, error) {
		m.attempts++
		return backoffDelay(m.attempts - 1), err
	}
	if err := crashCheck(m.log); err != nil {
		return fail(err)
	}
	if moduleLoaded() {
		// 上次进程被 SIGKILL（Close 的 rmmod 未跑）等残留的已载模块：
		// 先卸再装，否则 insmod 永远 EEXIST，采集面死循环。
		if out, err := runCmd("rmmod", moduleName); err != nil {
			return fail(fmt.Errorf("rmmod stale %s: %w: %s", moduleName, err, out))
		}
	}
	if out, err := runCmd("insmod", m.koPath); err != nil {
		return fail(fmt.Errorf("insmod %s: %w: %s", m.koPath, err, out))
	}
	m.loaded = true // insmod 成功即持有模块：下方失败路径的 unload 才会真正 rmmod
	if err := waitProc(ctx, procEndpoint, procWait); err != nil {
		m.unload() // 加载了但数据面没起来，按失败退避重走
		return fail(err)
	}
	m.attempts = 0
	return 0, nil
}

// moduleLoaded 报告 xiezhi_driver 是否已驻留内核（/proc/modules 首列即模块名）。
func moduleLoaded() bool {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	return moduleLoadedIn(string(data))
}

func moduleLoadedIn(procModules string) bool {
	for _, line := range strings.Split(procModules, "\n") {
		if name, _, _ := strings.Cut(line, " "); name == moduleName {
			return true
		}
	}
	return false
}

// unload 幂等：未加载时是空操作，rmmod 失败只记日志。
func (m *manager) unload() {
	if !m.loaded {
		return
	}
	m.loaded = false
	if out, err := runCmd("rmmod", moduleName); err != nil {
		m.log.Warn("rmmod failed", "err", err, "output", out)
	}
}

func waitProc(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%s not present after %s", path, timeout)
		}
		if err := sleepCtx(ctx, 50*time.Millisecond); err != nil {
			return ctx.Err()
		}
	}
}

// runCmd 找命令（PATH 外补 /usr/sbin、/sbin，systemd 单元 PATH 常缺这两处）
// 并执行，返回合并输出。
func runCmd(name string, args ...string) (string, error) {
	bin, err := lookCmd(name)
	if err != nil {
		return "", err
	}
	out, err := exec.Command(bin, args...).CombinedOutput()
	return string(out), err
}

func lookCmd(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range []string{"/usr/sbin", "/sbin"} {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH, /usr/sbin or /sbin", name)
}
