// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	pb "github.com/xycxmz/xiezhi-public/proto"
)

type condKind uint8

const (
	opIncl condKind = iota
	opEqu
	opNeq
	opRegex
	opStart
	opEnd
	opMt
	opLt
)

var kindByName = map[string]condKind{
	"INCL": opIncl, "EQU": opEqu, "NEQ": opNeq, "REGEX": opRegex,
	"START": opStart, "END": opEnd, "MT": opMt, "LT": opLt,
}

var severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

type compiledCond struct {
	kind    condKind
	path    []string // 点路径分段，如 [execve proc argv 0]
	strVal  string
	numVal  float64 // 编译期解析好的数值（可用则 numOK=true），供数值分派与 MT/LT
	numOK   bool
	re      *regexp.Regexp
	elemAll bool // 数组元素间逻辑：true=all/and，false=any/or（默认）
}

type compiledRule struct {
	id        string
	eventType pb.EventType
	severity  string
	mitre     string
	all       bool // conditions 间逻辑：true=and（默认），false=or
	conds     []compiledCond
}

// compileRule 把 rawRule 编译为可执行规则；schema 违规在此全量拒绝。
func compileRule(raw *rawRule) (*compiledRule, error) {
	if raw.typ != "field" {
		return nil, fmt.Errorf("type 必须为 field（intent 是 M4 的），得到 %q", raw.typ)
	}
	if raw.action != "alert" {
		return nil, fmt.Errorf("action 必须为 alert，得到 %q", raw.action)
	}
	if raw.id == "" {
		return nil, fmt.Errorf("id 不能为空")
	}
	et, ok := pb.EventType_value[raw.event]
	if !ok {
		return nil, fmt.Errorf("未知事件类型 %q", raw.event)
	}
	if !severities[raw.severity] {
		return nil, fmt.Errorf("severity 非法 %q", raw.severity)
	}
	r := &compiledRule{id: raw.id, eventType: pb.EventType(et), severity: raw.severity, mitre: raw.mitre}
	switch raw.matchLogic {
	case "", "and":
		r.all = true
	case "or":
		r.all = false
	default:
		return nil, fmt.Errorf("match.logic 非法 %q", raw.matchLogic)
	}
	if len(raw.conds) == 0 {
		return nil, fmt.Errorf("match.conditions 为空")
	}
	for i, rc := range raw.conds {
		kind, ok := kindByName[rc.op]
		if !ok {
			return nil, fmt.Errorf("condition[%d]: 未知算子 %q", i, rc.op)
		}
		if rc.field == "" {
			return nil, fmt.Errorf("condition[%d]: field 不能为空", i)
		}
		segs := strings.Split(rc.field, ".")
		for _, s := range segs {
			if s == "" {
				return nil, fmt.Errorf("condition[%d]: 字段路径含空段", i)
			}
		}
		if !rc.hasValue || rc.value == "" {
			return nil, fmt.Errorf("condition[%d]: value 不能为空", i)
		}
		cc := compiledCond{kind: kind, path: segs, strVal: rc.value}
		if n, err := strconv.ParseFloat(strings.TrimSpace(rc.value), 64); err == nil {
			cc.numVal, cc.numOK = n, true
		}
		switch rc.logic {
		case "", "any", "or":
			cc.elemAll = false
		case "all", "and":
			cc.elemAll = true
		default:
			return nil, fmt.Errorf("condition[%d]: 元素 logic 非法 %q", i, rc.logic)
		}
		switch kind {
		case opRegex:
			re, err := regexp.Compile(rc.value)
			if err != nil {
				return nil, fmt.Errorf("condition[%d]: REGEX 编译失败: %w", i, err)
			}
			cc.re = re
		case opMt, opLt:
			if !cc.numOK {
				return nil, fmt.Errorf("condition[%d]: %s 需要数值 value，得到 %q", i, rc.op, rc.value)
			}
		}
		r.conds = append(r.conds, cc)
	}
	return r, nil
}

// ruleset 是一次加载产出的不可变规则快照，热更用原子指针整体换。
type ruleset struct {
	version string // 文件集内容哈希（十六进制前 16 位）
	byEvent map[pb.EventType][]*compiledRule
	total   int
}

type loadResult struct {
	set      *ruleset
	rejected int
}

func readRuleFiles(dir string) ([]string, [][]byte, error) {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var names []string
	for _, e := range es {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	out := make([][]byte, len(names))
	for i, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, nil, err
		}
		out[i] = b
	}
	return names, out, nil
}

// dirDigest 对文件集（排序后 文件名+内容）做哈希，热更轮询只比对它。
func dirDigest(dir string) (string, error) {
	names, contents, err := readRuleFiles(dir)
	if err != nil {
		return "", err
	}
	return digestOf(names, contents), nil
}

func digestOf(names []string, contents [][]byte) string {
	h := sha256.New()
	for i := range names {
		h.Write([]byte(names[i]))
		h.Write([]byte{0})
		h.Write(contents[i])
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// loadDir 加载目录下全部 *.yaml；坏规则跳过并计数（带告警日志），不废整批。
func loadDir(dir string) (*loadResult, error) {
	// 只读一次盘：验签、解析、version 摘要共用同一批字节。若各自读盘，
	// 验证的字节与实际解析/摘要的字节可来自不同时刻的目录（R3.5 verify-
	// before-load 竞态：验签读合法内容、解析读偷换后的恶意内容）。
	names, contents, err := readRuleFiles(dir)
	if err != nil {
		return nil, err
	}
	// R3.5: verify manifest signature before loading (no manifest = dev mode)
	if err := verifyDirSignature(dir, names, contents); err != nil {
		return nil, fmt.Errorf("rules signature verification: %w", err)
	}
	slog.Info("rules: manifest signature verified", "dir", dir)
	v := digestOf(names, contents)
	res := &loadResult{set: &ruleset{version: v, byEvent: make(map[pb.EventType][]*compiledRule, 8)}}
	ids := map[string]string{}
	for i, name := range names {
		raw, err := parseRuleYAML(contents[i])
		if err != nil {
			res.rejected++
			slog.Warn("rules: 跳过坏规则", "file", name, "err", err)
			continue
		}
		cr, err := compileRule(raw)
		if err != nil {
			res.rejected++
			slog.Warn("rules: 跳过坏规则", "file", name, "err", err)
			continue
		}
		if prev, dup := ids[cr.id]; dup {
			res.rejected++
			slog.Warn("rules: 跳过重复规则 id", "file", name, "id", cr.id, "first_seen_in", prev)
			continue
		}
		ids[cr.id] = name
		res.set.byEvent[cr.eventType] = append(res.set.byEvent[cr.eventType], cr)
		res.set.total++
	}
	return res, nil
}
