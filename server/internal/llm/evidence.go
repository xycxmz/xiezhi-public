// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xycxmz/xiezhi-public/server/internal/pipeline"
)

// Untrusted 标记攻击者可控字符串（argv/文件名/日志行/事件原文）。MarshalJSON
// 永远输出 {"untrusted":"..."} 结构，system prompt 声明该结构是数据不是指令
// （防注入四件套之一：不可信内容隔离标记）。
type Untrusted string

func (u Untrusted) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"untrusted": string(u)})
}

// UnmarshalJSON 接受裸字符串（模型按 schema 输出的形态）与 {"untrusted":"..."}
// 包裹形态（下游角色重新投喂上游产出时的形态），两种输入都归一为同一个字符串，
// 不产生新的非法状态。
func (u *Untrusted) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*u = Untrusted(s)
		return nil
	}
	var w struct {
		Untrusted string `json:"untrusted"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*u = Untrusted(w.Untrusted)
	return nil
}

// Evidence 是单条告警的证据包（模板裁剪：告警元数据 → 触发事件 →
// 同 agent 近期事件摘要 → 进程树）。
type Evidence struct {
	Alert struct {
		TsMs     int64     `json:"ts_ms"`
		AgentID  Untrusted `json:"agent_id"` // agent 自报、服务端不校验（gRPC 仅共享 token/mTLS CA），按不可信隔离
		Hostname Untrusted `json:"hostname"` // 同上：事件头自报字段
		RuleID   string    `json:"rule_id"`
		Severity string    `json:"severity"`
		Mitre    string    `json:"mitre,omitempty"`
		Summary  Untrusted `json:"summary"` // rule 命中描述/firstseen 键，含事件可控串
	} `json:"alert"`
	// TriggerEvent 截 2KB。firstseen 告警无 EventRef，此段为空。
	TriggerEvent Untrusted `json:"trigger_event,omitempty"`
	// RecentEvents 同 agent 时间窗内倒序（最新在前），每条 Body 截 200B。
	RecentEvents []RecentEvent `json:"recent_events"`
	// ProcessTree 是 session.SubtreeJSON 的缩进树文本，截 4KB；拿不到 pid 则空。
	ProcessTree Untrusted `json:"process_tree,omitempty"`
}

// RecentEvent 单条历史事件摘要。TsMs/Type 可信，Body 攻击者可控。
type RecentEvent struct {
	TsMs int64     `json:"ts_ms"`
	Type string    `json:"type"`
	Body Untrusted `json:"body"`
}

const (
	// triggerEventMaxBytes 与事件侧 event_ref 的 4KB 截断对齐：此前 2KB
	// 二次截断丢 argv 深段，是研判证据损失点之一（证据加厚后收紧）。
	triggerEventMaxBytes = 4 * 1024
	recentBodyMaxBytes   = 200
	processTreeMaxBytes  = 4 * 1024

	// evidenceBudgetBytes 是 8K token 的字节预算（≈3 B/token 保守换算）。
	// 超预算从 recent_events 尾部（最旧）逐条丢弃。
	evidenceBudgetBytes = 24576
)

// BuildEvidence 组装单条告警的证据包。fetchers/trees 任一为 nil 即跳过该段
// （缺证据不阻断研判——LLM 会给 insufficient_evidence，这正是三态的用途）。
// sinceMs 之前的告警不打包（调用方已按 TriageSinceMin 过滤）。
func BuildEvidence(ctx context.Context, a *pipeline.Alert, sinceMs int64, fetcher EventFetcher, trees SubtreeSource) (*Evidence, error) {
	if a == nil {
		return nil, fmt.Errorf("llm: nil alert")
	}
	ev := &Evidence{}
	ev.Alert.TsMs = a.TsMs
	ev.Alert.AgentID = Untrusted(a.AgentID)
	ev.Alert.Hostname = Untrusted(a.Hostname)
	ev.Alert.RuleID = a.RuleID
	ev.Alert.Severity = a.Severity
	ev.Alert.Mitre = a.Mitre
	ev.Alert.Summary = Untrusted(truncBytes(a.Summary, triggerEventMaxBytes))
	if a.EventRef != "" {
		ev.TriggerEvent = Untrusted(truncBytes(a.EventRef, triggerEventMaxBytes))
	}

	if fetcher != nil && a.AgentID != "" {
		// 拉宽候选集后按触发进程相关性重排：同 pid 的历史事件（网络/文件/
		// 后续 exec）是攻击链上下文，优先于同 agent 的无关噪音——此前
		// 20 条全类型混装对研判几乎无信息量。
		if rows, err := fetcher.RecentByAgent(ctx, a.AgentID, sinceMs, 100); err == nil && len(rows) > 0 {
			if pid := pidFromEventRef(a.EventRef); pid > 0 {
				// F-008：精确值匹配——"pid":42 是 "pid":421 的子串，必须
				// 校验 pid 数字串的下一字符（, 或 }）才认定命中。
				relevant := make([]EventSummary, 0, len(rows))
				rest := make([]EventSummary, 0, len(rows))
				for _, r := range rows {
					if pidExactInBody(r.Body, pid) {
						relevant = append(relevant, r)
					} else {
						rest = append(rest, r)
					}
				}
				rows = append(relevant, rest...)
			}
			if len(rows) > 20 {
				rows = rows[:20]
			}
			ev.RecentEvents = make([]RecentEvent, 0, len(rows))
			for _, r := range rows {
				ev.RecentEvents = append(ev.RecentEvents, RecentEvent{
					TsMs: r.TsMs,
					Type: r.Type,
					Body: Untrusted(truncBytes(r.Body, recentBodyMaxBytes)),
				})
			}
		}
	}

	if trees != nil && a.Hostname != "" {
		if pid := pidFromEventRef(a.EventRef); pid > 0 {
			// depth 8：提权/容器链常见 4-5 层，depth 4 会截掉树根锚点。
			if tree, err := trees.SubtreeJSON(a.Hostname, pid, 8); err == nil && tree != "" {
				ev.ProcessTree = Untrusted(truncBytes(tree, processTreeMaxBytes))
			}
		}
	}
	return ev, nil
}

// MarshalBudgeted 序列化证据并在超预算时从 recent_events 尾部（最旧）逐条
// 丢弃后重排。固定段（alert/trigger_event/process_tree）各有字节上界，
// 丢光 recent 后总长必低于预算，不存在无法收敛的输入。
func (e *Evidence) MarshalBudgeted() ([]byte, error) {
	b, err := marshalNoEscape(e)
	if err != nil {
		return nil, err
	}
	for len(b) > evidenceBudgetBytes && len(e.RecentEvents) > 0 {
		e.RecentEvents = e.RecentEvents[:len(e.RecentEvents)-1]
		if b, err = marshalNoEscape(e); err != nil {
			return nil, err
		}
	}
	// F-009 兜底：控制字节的 \u00XX 转义仍可能让单个固定段击穿预算
	//（丢光 recent 后循环无计可施），按预算三等分截固定段保总量。
	if len(b) > evidenceBudgetBytes {
		if e.TriggerEvent != "" {
			e.TriggerEvent = Untrusted(truncBytes(string(e.TriggerEvent), evidenceBudgetBytes/3))
		}
		if e.ProcessTree != "" {
			e.ProcessTree = Untrusted(truncBytes(string(e.ProcessTree), evidenceBudgetBytes/3))
		}
		if b, err = marshalNoEscape(e); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// marshalNoEscape 关闭 HTML 转义：Go 默认把 &/</> 转义为 \u0026 形态
//（1B→6B），是攻击者可控 argv 击穿预算的主源；注入隔离已由 Untrusted
// 包裹承担，无需 HTML 转义（F-009）。
func marshalNoEscape(v any) ([]byte, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(sb.String(), "\n")), nil
}

// pidPaths 是 EventRef（事件 protojson）到主体 pid 的路径表，按检测层实际
// 产出的事件形态排列；EventRef 截断可能切断深字段，逐路径取第一个命中。
var pidPaths = []string{
	"execve.proc.pid", "net.proc.pid", "dns.proc.pid", "file.proc.pid",
	"memExec.proc.pid", "kernelModule.proc.pid", "ptrace.tracer.pid",
	"misc.proc.pid", "exit.pid", "fork.childPid", "cred.pid",
}

// pidFromEventRef 从触发事件 JSON 推断主体 pid。firstseen 告警无 EventRef
// 或 JSON 不可解析（截断）时返回 0，调用方跳过进程树段。
func pidFromEventRef(ref string) int32 {
	if ref == "" {
		return 0
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(ref), &root); err != nil {
		return 0
	}
	for _, p := range pidPaths {
		segs := strings.Split(p, ".")
		var cur any = root
		ok := true
		for _, s := range segs {
			m, isMap := cur.(map[string]any)
			if !isMap {
				ok = false
				break
			}
			cur, ok = m[s]
			if !ok {
				break
			}
		}
		if !ok {
			continue
		}
		switch v := cur.(type) {
		case float64:
			if v > 0 && v == float64(int32(v)) {
				return int32(v)
			}
		case string:
			if n, err := strconv.ParseInt(v, 10, 32); err == nil && n > 0 {
				return int32(n)
			}
		}
	}
	return 0
}

// pidExactInBody 判断事件体 JSON 是否含该 pid 的精确 `"pid":<n>` 值
// （含字符串化变体），排除更长 pid 的数字前缀误配（F-008）。
func pidExactInBody(body string, pid int32) bool {
	pat := fmt.Sprintf(`"pid":%d`, pid)
	for from := 0; ; {
		i := strings.Index(body[from:], pat)
		if i < 0 {
			break
		}
		i += from
		from = i + 1
		j := i + len(pat)
		if j >= len(body) || (body[j] != ',' && body[j] != '}') {
			continue // 数字继续延伸：是更长 pid 的前缀
		}
		return true
	}
	patQ := fmt.Sprintf(`"pid":"%d"`, pid)
	return strings.Contains(body, patQ)
}

// truncBytes 按字节截断并在截断处标记省略号（不劈 UTF-8 多字节序列的显示，
// 尾部非法字节由 JSON 序列化兜底替换）。
func truncBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	for len(cut) > 0 && !utf8TailOK(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "...(truncated)"
}

// utf8TailOK 报告 s 末尾是否不落在多字节序列中间。
func utf8TailOK(s string) bool {
	if len(s) == 0 {
		return true
	}
	i := len(s) - 1
	if s[i] < 0x80 {
		return true
	}
	start := i
	for i >= 0 && start-i < 3 && s[i]&0xC0 == 0x80 {
		i--
	}
	if i < 0 || i < start-3 {
		return false
	}
	switch {
	case s[i]&0xE0 == 0xC0:
		return start-i == 1
	case s[i]&0xF0 == 0xE0:
		return start-i == 2
	case s[i]&0xF8 == 0xF0:
		return start-i == 3
	}
	return false
}
