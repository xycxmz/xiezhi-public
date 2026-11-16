// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"unicode"
)

// 严格块式 YAML 子集解析器，只认冻结 schema 的形态：顶层标量键 + match 一层
// 嵌套 + conditions 一层列表（列表项为扁平键值）。流式/锚点/多文档/Tab 缩进/
// 未知键一律加载期报错——宁可拒绝坏文件，不让规则被静默误读。
// 若日后 go.mod 引入 yaml.v3，替换本文件即可，其余代码只依赖 rawRule。

type rawRule struct {
	id, typ, event, severity, mitre, action string
	matchLogic                              string
	conds                                   []rawCondition
}

type rawCondition struct {
	op, field, value, logic string
	hasValue                bool
}

type yLine struct {
	indent int
	text   string
	num    int
}

func scanYAMLLines(src string) ([]yLine, error) {
	var out []yLine
	for i, raw := range strings.Split(src, "\n") {
		line := strings.TrimRight(raw, " \r")
		trimmed := strings.TrimLeft(line, " ")
		if trimmed != "" && trimmed[0] == '\t' {
			return nil, fmt.Errorf("line %d: 缩进不允许 Tab", i+1)
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, yLine{indent: len(line) - len(trimmed), text: trimmed, num: i + 1})
	}
	return out, nil
}

// splitKV 在首个后跟空格或行尾的冒号处切分；键限定为标识符字符。
func splitKV(l yLine) (key, val string, err error) {
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
	key = l.text[:idx]
	for _, r := range key {
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return "", "", fmt.Errorf("line %d: 非法键 %q", l.num, key)
		}
	}
	return key, strings.TrimLeft(l.text[idx+1:], " "), nil
}

func parseRuleYAML(src []byte) (*rawRule, error) {
	lines, err := scanYAMLLines(string(src))
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("空规则文件")
	}
	r := &rawRule{}
	seen := map[string]bool{}
	i := 0
	for i < len(lines) {
		l := lines[i]
		if l.indent != 0 {
			return nil, fmt.Errorf("line %d: 意外缩进", l.num)
		}
		key, rawVal, err := splitKV(l)
		if err != nil {
			return nil, err
		}
		switch key {
		case "id", "type", "event", "severity", "mitre", "action", "match":
		default:
			return nil, fmt.Errorf("line %d: 未知顶层键 %q", l.num, key)
		}
		if seen[key] {
			return nil, fmt.Errorf("line %d: 顶层键 %q 重复", l.num, key)
		}
		seen[key] = true
		if key == "match" {
			if rawVal != "" {
				return nil, fmt.Errorf("line %d: match 需为块（不接受行内值）", l.num)
			}
			i, err = parseMatchBlock(lines, i+1, r)
			if err != nil {
				return nil, err
			}
			continue
		}
		v, err := parseScalarVal(rawVal, l.num)
		if err != nil {
			return nil, err
		}
		switch key {
		case "id":
			r.id = v
		case "type":
			r.typ = v
		case "event":
			r.event = v
		case "severity":
			r.severity = v
		case "mitre":
			r.mitre = v
		case "action":
			r.action = v
		}
		i++
	}
	return r, nil
}

func parseMatchBlock(lines []yLine, i int, r *rawRule) (int, error) {
	if i >= len(lines) || lines[i].indent == 0 {
		return 0, fmt.Errorf("match 块为空")
	}
	ind := lines[i].indent
	seen := map[string]bool{}
	for i < len(lines) && lines[i].indent == ind {
		l := lines[i]
		key, rawVal, err := splitKV(l)
		if err != nil {
			return 0, err
		}
		if seen[key] {
			return 0, fmt.Errorf("line %d: match 内键 %q 重复", l.num, key)
		}
		switch key {
		case "logic":
			r.matchLogic, err = parseScalarVal(rawVal, l.num)
			if err != nil {
				return 0, err
			}
			seen[key] = true
			i++
		case "conditions":
			if rawVal != "" {
				return 0, fmt.Errorf("line %d: conditions 需为块", l.num)
			}
			i, err = parseCondList(lines, i+1, ind, r)
			if err != nil {
				return 0, err
			}
			seen[key] = true
		default:
			return 0, fmt.Errorf("line %d: match 内未知键 %q", l.num, key)
		}
	}
	if i < len(lines) && lines[i].indent > ind {
		return 0, fmt.Errorf("line %d: 意外深缩进", lines[i].num)
	}
	return i, nil
}

// parseCondList 解析 “- ” 列表项；列表项首对键值跟在短横线后，
// 其余键必须与首键严格对齐（短横线缩进 +2）。
func parseCondList(lines []yLine, i int, parentInd int, r *rawRule) (int, error) {
	if i >= len(lines) || lines[i].indent <= parentInd {
		return 0, fmt.Errorf("conditions 列表为空")
	}
	entryInd := lines[i].indent
	for i < len(lines) && lines[i].indent == entryInd {
		l := lines[i]
		if !strings.HasPrefix(l.text, "- ") {
			return 0, fmt.Errorf("line %d: 期待列表项 “- 键: 值”", l.num)
		}
		c := rawCondition{}
		ck := map[string]bool{}
		first := yLine{indent: entryInd + 2, text: l.text[2:], num: l.num}
		if err := setCondField(&c, first, ck); err != nil {
			return 0, err
		}
		i++
		for i < len(lines) && lines[i].indent == entryInd+2 {
			if err := setCondField(&c, lines[i], ck); err != nil {
				return 0, err
			}
			i++
		}
		if i < len(lines) && lines[i].indent > entryInd+2 {
			return 0, fmt.Errorf("line %d: 意外深缩进", lines[i].num)
		}
		if i < len(lines) && lines[i].indent > parentInd && lines[i].indent < entryInd {
			return 0, fmt.Errorf("line %d: 列表项缩进不齐", lines[i].num)
		}
		r.conds = append(r.conds, c)
	}
	return i, nil
}

func setCondField(c *rawCondition, l yLine, seen map[string]bool) error {
	key, rawVal, err := splitKV(l)
	if err != nil {
		return err
	}
	switch key {
	case "op", "field", "value", "logic":
	default:
		return fmt.Errorf("line %d: condition 内未知键 %q", l.num, key)
	}
	if seen[key] {
		return fmt.Errorf("line %d: condition 内键 %q 重复", l.num, key)
	}
	seen[key] = true
	v, err := parseScalarVal(rawVal, l.num)
	if err != nil {
		return err
	}
	switch key {
	case "op":
		c.op = v
	case "field":
		c.field = v
	case "value":
		c.value, c.hasValue = v, true
	case "logic":
		c.logic = v
	}
	return nil
}

// parseScalarVal 解析值位置的标量：空串、注释起始、单/双引号、裸标量。
func parseScalarVal(raw string, ln int) (string, error) {
	if raw == "" || raw[0] == '#' {
		return "", nil
	}
	switch raw[0] {
	case '\'':
		s, rest, err := scanSingleQuoted(raw, ln)
		if err != nil {
			return "", err
		}
		return s, checkRest(rest, ln)
	case '"':
		s, rest, err := scanDoubleQuoted(raw, ln)
		if err != nil {
			return "", err
		}
		return s, checkRest(rest, ln)
	}
	if strings.HasPrefix(raw, "- ") || raw == "-" {
		return "", fmt.Errorf("line %d: 值位置不支持行内序列", ln)
	}
	v := raw
	if j := strings.Index(v, " #"); j >= 0 {
		v = v[:j]
	}
	v = strings.TrimRight(v, " ")
	if strings.Contains(v, ": ") || strings.HasSuffix(v, ":") {
		return "", fmt.Errorf("line %d: 裸值含 “:”（嵌套映射不支持）: %q", ln, v)
	}
	return v, nil
}

func scanSingleQuoted(s string, ln int) (val, rest string, err error) {
	var b strings.Builder
	i := 1
	for i < len(s) {
		if s[i] == '\'' {
			if i+1 < len(s) && s[i+1] == '\'' {
				b.WriteByte('\'')
				i += 2
				continue
			}
			return b.String(), s[i+1:], nil
		}
		b.WriteByte(s[i])
		i++
	}
	return "", "", fmt.Errorf("line %d: 单引号未闭合", ln)
}

func scanDoubleQuoted(s string, ln int) (val, rest string, err error) {
	var b strings.Builder
	i := 1
	for i < len(s) {
		switch s[i] {
		case '"':
			return b.String(), s[i+1:], nil
		case '\\':
			if i+1 >= len(s) {
				return "", "", fmt.Errorf("line %d: 双引号未闭合", ln)
			}
			switch s[i+1] {
			case '"', '\\':
				b.WriteByte(s[i+1])
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				return "", "", fmt.Errorf("line %d: 不支持的转义 \\%c", ln, s[i+1])
			}
			i += 2
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return "", "", fmt.Errorf("line %d: 双引号未闭合", ln)
}

func checkRest(rest string, ln int) error {
	rest = strings.TrimLeft(rest, " ")
	if rest == "" || strings.HasPrefix(rest, "#") {
		return nil
	}
	return fmt.Errorf("line %d: 引号后有多余内容 %q", ln, rest)
}
