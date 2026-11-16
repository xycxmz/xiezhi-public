// SPDX-License-Identifier: Apache-2.0

// digest.go 是 first-seen 降噪层（M4）：exe 白名单前缀 + host×kind 小时聚合。
// 新键不再逐条发 info 告警，改为（白名单外的）按 (host, kind, 观察小时)
// 聚合，小时关闭后发一条 digest 告警（rule_id=firstseen/<kind>/digest）；
// 停机时 flushAll 把未满小时的窗口也发掉，不丢已降噪的信息。
package firstseen

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
)

// envExePrefixes 覆盖默认白名单：逗号分隔的 exe 路径前缀。白名单内的 exe
// 首见只记录键（PG 行照写），完全压告警——系统路径下的海量合法首见是
// M3 首日噪声的主要来源（AGENTS.md 降噪序第一步）。
const envExePrefixes = "XIEZHI_FIRSTSEEN_EXE_PREFIXES"

const msPerHour = int64(time.Hour / time.Millisecond)

func defaultExePrefixes() []string {
	return []string{"/usr", "/bin", "/sbin", "/lib", "/opt", "/snap", "/etc"}
}

// ExePrefixesFromEnv 返回生效的 exe 白名单前缀：env 非空按其解析，空则默认表。
func ExePrefixesFromEnv() []string {
	if v := os.Getenv(envExePrefixes); v != "" {
		return ParseExePrefixes(v)
	}
	return defaultExePrefixes()
}

// ParseExePrefixes 解析逗号分隔前缀表：trim 空白、丢空项，全空返回 nil。
func ParseExePrefixes(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// KeyKind 解出键的类别段（键编码首段）。跨包消费（replay 统计）用。
func KeyKind(key string) string {
	if i := strings.Index(key, keySep); i > 0 {
		return key[:i]
	}
	return ""
}

// KeyExePath 从 KindExe 键解出 exe 路径；其他 kind 返回 ok=false。
func KeyExePath(key string) (string, bool) {
	parts := strings.Split(key, keySep)
	if len(parts) != 3 || parts[0] != KindExe {
		return "", false
	}
	return parts[2], true
}

// digestKey 定位一条小时聚合：host × kind × 观察时间戳所在整点小时。
type digestKey struct {
	host string
	kind string
	hour int64 // Unix 毫秒、整点对齐
}

type digestWindow struct {
	count   uint64
	agentID string // 该窗口首个观察的 agent（host↔agent 实际一一对应）
}

// digest 把全局新键聚合成小时 digest 告警。所有权归 Handler.loop 单
// goroutine（add/flush 均只从批量循环调用），无需加锁。
type digest struct {
	prefixes []string
	sink     pipeline.Sink
	windows  map[digestKey]*digestWindow
}

func newDigest(prefixes []string, sink pipeline.Sink) *digest {
	return &digest{prefixes: prefixes, sink: sink, windows: make(map[digestKey]*digestWindow)}
}

func (d *digest) whitelisted(o Obs) bool {
	if o.Kind != KindExe {
		return false
	}
	exe, ok := KeyExePath(o.Key)
	if !ok {
		return false
	}
	for _, p := range d.prefixes {
		if strings.HasPrefix(exe, p) {
			return true
		}
	}
	return false
}

// add 归档一个全局新键（PG 层已判新、行已照写）。白名单内 exe 到此为止
// （只压告警）；其余进对应小时窗口，等 digest 告警。
func (d *digest) add(o Obs) {
	if d.whitelisted(o) {
		return
	}
	k := digestKey{host: o.Host, kind: o.Kind, hour: o.TsMs / msPerHour * msPerHour}
	w := d.windows[k]
	if w == nil {
		w = &digestWindow{agentID: o.AgentID}
		d.windows[k] = w
	}
	w.count++
}

// flush 发出所有已结束小时（hour+1h <= now）的窗口。按 hour/host/kind 排序
// 保证输出确定。context.Background：digest 是停机路径也要走的告警，不挂
// 任何请求 ctx。
func (d *digest) flush(now time.Time) {
	d.flushBefore(now.UnixMilli())
}

// flushAll 无视小时是否结束全部发出（Handler 停机/回放收尾用）。
func (d *digest) flushAll(now time.Time) {
	d.emit(d.closedKeys(func(k digestKey) bool { return true }), now.UnixMilli())
}

func (d *digest) flushBefore(nowMs int64) {
	d.emit(d.closedKeys(func(k digestKey) bool { return k.hour+msPerHour <= nowMs }), nowMs)
}

func (d *digest) closedKeys(closed func(digestKey) bool) []digestKey {
	keys := make([]digestKey, 0, len(d.windows))
	for k := range d.windows {
		if closed(k) {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].hour != keys[j].hour {
			return keys[i].hour < keys[j].hour
		}
		if keys[i].host != keys[j].host {
			return keys[i].host < keys[j].host
		}
		return keys[i].kind < keys[j].kind
	})
	return keys
}

func (d *digest) emit(keys []digestKey, nowMs int64) {
	for _, k := range keys {
		w := d.windows[k]
		d.sink.EmitAlert(context.Background(), &pipeline.Alert{
			TsMs:     nowMs,
			AgentID:  w.agentID,
			Hostname: k.host,
			RuleID:   "firstseen/" + k.kind + "/digest",
			Severity: "info",
			Summary:  fmt.Sprintf("host %s kind %s 首见 %d 条（白名单外）", k.host, k.kind, w.count),
		})
		delete(d.windows, k)
	}
}
