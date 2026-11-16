// SPDX-License-Identifier: Apache-2.0

package intent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/xycxmz/xiezhi-public/server/internal/rules"
)

// policy 是策略快照（rules/intent/policy.yaml，格式冻结，
// SecEBL tag_risk_policy 裁剪）。快照整体换（atomic.Pointer），nil = 旁路。
//
// tags: 标签→静态分（-1.0~10.0，负分是良性抵扣语义）
// threshold: 会话累加阈值（折后总分 ≥ 阈值告警）
// maintenance_discount / maintenance_tags: 维护标签占比 >50% 时总分乘的
// 衰减因子与维护标签集——负上下文信号，不是白名单。
type policy struct {
	tags          map[string]float64
	threshold     float64
	maintDiscount float64
	maintTags     map[string]struct{}
	version       string
}

// loadPolicy 读并解析策略文件。missing=true 仅在「目录未被签名管理」时
// 合法（dev 旁路）；签名目录内 policy 缺失或验签失败一律 err——防删除
// 文件绕过签名通道让整层静默（R8.4 审计 R-1/R-2）。单次读盘、验证与
// 解析共用同一批字节，消除 verify-before-load TOCTOU。
func loadPolicy(path string) (pol *policy, missing bool, err error) {
	dir := filepath.Dir(path)
	names, contents, rerr := rules.ReadRuleFiles(dir)
	if rerr != nil {
		return nil, false, rerr
	}
	idx := -1
	want := filepath.Base(path)
	for i, n := range names {
		if n == want {
			idx = i
			break
		}
	}
	if idx < 0 {
		// 文件不在：签名管理的目录（manifest 在）或 REQUIRE_SIGNATURE=1
		// 时 fail-closed——manifest 列了它却被删是篡改路径。
		if rules.DirHasManifest(dir) || rules.RequireSignedRules() {
			return nil, false, fmt.Errorf("policy %s missing from signed dir (tamper path)", path)
		}
		return nil, true, nil
	}
	if err := rules.VerifyFiles(dir, names, contents); err != nil {
		return nil, false, fmt.Errorf("policy dir signature: %w", err)
	}
	pol, err = parsePolicy(string(contents[idx]))
	if err != nil {
		return nil, false, err
	}
	sum := sha256.Sum256(contents[idx])
	pol.version = hex.EncodeToString(sum[:])[:12]
	return pol, false, nil
}

type polLine struct {
	indent int
	text   string
	num    int
}

func scanLines(src string) ([]polLine, error) {
	var out []polLine
	for i, raw := range strings.Split(src, "\n") {
		line := strings.TrimRight(raw, " \r")
		trimmed := strings.TrimLeft(line, " ")
		if trimmed != "" && trimmed[0] == '\t' {
			return nil, fmt.Errorf("line %d: 缩进不允许 Tab", i+1)
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, polLine{indent: len(line) - len(trimmed), text: trimmed, num: i + 1})
	}
	return out, nil
}

// parsePolicy 只认冻结 schema 的形态：顶层标量键（threshold /
// maintenance_discount）+ tags 一层映射 + maintenance_tags（行内流式列表
// 或块式列表）。未知键、重复键、Tab、嵌套映射一律报错——宁可拒绝坏文件，
// 不让分值被静默误读（与 rules/yaml.go 同款纪律）。
func parsePolicy(src string) (*policy, error) {
	lines, err := scanLines(src)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("策略文件为空")
	}
	p := &policy{
		tags:          make(map[string]float64),
		maintTags:     make(map[string]struct{}),
		maintDiscount: 1.0,
	}
	seen := map[string]bool{}
	i := 0
	for i < len(lines) {
		l := lines[i]
		if l.indent != 0 {
			return nil, fmt.Errorf("line %d: 意外缩进 %q", l.num, l.text)
		}
		key, val, err := splitTopKV(l)
		if err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, fmt.Errorf("line %d: 顶层键 %q 重复", l.num, key)
		}
		seen[key] = true
		switch key {
		case "tags":
			i, err = parseTagsBlock(lines, i+1, p)
		case "maintenance_tags":
			i, err = parseTagList(lines, i, val, p)
		case "threshold":
			if p.threshold, err = parseScore(val, l.num, "threshold"); err != nil {
				return nil, err
			}
			i++
		case "maintenance_discount":
			if p.maintDiscount, err = parseScore(val, l.num, "maintenance_discount"); err != nil {
				return nil, err
			}
			i++
		default:
			return nil, fmt.Errorf("line %d: 未知顶层键 %q", l.num, key)
		}
		if err != nil {
			return nil, err
		}
	}
	if len(p.tags) == 0 {
		return nil, fmt.Errorf("tags 缺失或为空")
	}
	if p.threshold <= 0 {
		return nil, fmt.Errorf("threshold 缺失或非正: %v", p.threshold)
	}
	if p.maintDiscount <= 0 || p.maintDiscount > 1 {
		return nil, fmt.Errorf("maintenance_discount 须在 (0,1]: %v", p.maintDiscount)
	}
	for tag := range p.tags {
		if p.tags[tag] < -1.0 || p.tags[tag] > 10.0 {
			return nil, fmt.Errorf("标签 %q 分值 %v 越界 [-1.0,10.0]", tag, p.tags[tag])
		}
	}
	return p, nil
}

// splitTopKV 在首个后跟空格或行尾的冒号处切分顶层键值。
func splitTopKV(l polLine) (key, val string, err error) {
	idx := -1
	for i := 0; i < len(l.text); i++ {
		if l.text[i] == ':' && (i+1 == len(l.text) || l.text[i+1] == ' ') {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return "", "", fmt.Errorf("line %d: 期待 “键: 值”，得到 %q", l.num, l.text)
	}
	return l.text[:idx], strings.TrimLeft(l.text[idx+1:], " "), nil
}

// parseTagsBlock 解析 tags 块： `  tag_name: score`。
func parseTagsBlock(lines []polLine, i int, p *policy) (int, error) {
	if i >= len(lines) || lines[i].indent == 0 {
		return 0, fmt.Errorf("tags 块为空")
	}
	ind := lines[i].indent
	seen := map[string]bool{}
	for i < len(lines) && lines[i].indent == ind {
		l := lines[i]
		key, val, err := splitTopKV(l)
		if err != nil {
			return 0, err
		}
		if !validTagName(key) {
			return 0, fmt.Errorf("line %d: 非法标签名 %q", l.num, key)
		}
		if seen[key] {
			return 0, fmt.Errorf("line %d: 标签 %q 重复", l.num, key)
		}
		seen[key] = true
		score, err := parseScore(val, l.num, "tags."+key)
		if err != nil {
			return 0, err
		}
		p.tags[key] = score
		i++
	}
	if i < len(lines) && lines[i].indent > ind {
		return 0, fmt.Errorf("line %d: tags 不支持二层嵌套", lines[i].num)
	}
	return i, nil
}

// parseTagList 解析 maintenance_tags：行内流式 [a, b] 或块式列表。
func parseTagList(lines []polLine, i int, val string, p *policy) (int, error) {
	l := lines[i]
	if val == "" {
		return parseTagListBlock(lines, i+1, l, p)
	}
	names, err := parseFlowList(val, l.num)
	if err != nil {
		return 0, err
	}
	for _, n := range names {
		p.maintTags[n] = struct{}{}
	}
	return i + 1, nil
}

func parseTagListBlock(lines []polLine, i int, parent polLine, p *policy) (int, error) {
	if i >= len(lines) || lines[i].indent <= parent.indent {
		return 0, fmt.Errorf("line %d: maintenance_tags 块为空", parent.num)
	}
	ind := lines[i].indent
	for i < len(lines) && lines[i].indent == ind {
		l := lines[i]
		if !strings.HasPrefix(l.text, "- ") {
			return 0, fmt.Errorf("line %d: 期待列表项 “- 标签名”", l.num)
		}
		name := stripQuotes(strings.TrimSpace(l.text[2:]))
		if !validTagName(name) {
			return 0, fmt.Errorf("line %d: 非法标签名 %q", l.num, name)
		}
		p.maintTags[name] = struct{}{}
		i++
	}
	return i, nil
}

func parseFlowList(val string, ln int) ([]string, error) {
	v := strings.TrimSpace(val)
	if !strings.HasPrefix(v, "[") || !strings.HasSuffix(v, "]") {
		return nil, fmt.Errorf("line %d: maintenance_tags 行内值须为 [a, b] 流式列表", ln)
	}
	inner := strings.TrimSpace(v[1 : len(v)-1])
	if inner == "" {
		return nil, nil
	}
	parts := strings.Split(inner, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		name := stripQuotes(strings.TrimSpace(part))
		if !validTagName(name) {
			return nil, fmt.Errorf("line %d: 非法标签名 %q", ln, name)
		}
		out = append(out, name)
	}
	return out, nil
}

var tagNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func validTagName(s string) bool { return tagNameRe.MatchString(s) }

func stripQuotes(s string) string {
	if len(s) >= 2 && (s[0] == '\'' && s[len(s)-1] == '\'' || s[0] == '"' && s[len(s)-1] == '"') {
		return s[1 : len(s)-1]
	}
	return s
}

// parseScore 解析值位置的浮点数；裸标量或引号包裹均可。
func parseScore(val string, ln int, field string) (float64, error) {
	v := strings.TrimSpace(stripComment(val))
	v = stripQuotes(v)
	if v == "" {
		return 0, fmt.Errorf("line %d: %s 缺数值", ln, field)
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("line %d: %s 非浮点数 %q", ln, field, v)
	}
	return f, nil
}

func stripComment(s string) string {
	if j := strings.Index(s, " #"); j >= 0 {
		return s[:j]
	}
	return s
}
