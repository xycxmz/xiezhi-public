// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strconv"
	"strings"
)

// 字段路径语义（冻结）：protojson(camelCase) marshal 成 map 后的点路径+数组下标，
// 如 execve.proc.argv.0、header.agentId、net.port。resolvePath 逐段下钻，
// map 按键取、数组按下标取；任何一段不可下钻即视为字段缺失（=不命中）。
// JSON null 同样按缺失处理。
func resolvePath(root map[string]any, path []string) any {
	var cur any = root
	for _, seg := range path {
		switch t := cur.(type) {
		case map[string]any:
			v, ok := t[seg]
			if !ok {
				return nil
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(t) {
				return nil
			}
			cur = t[idx]
		default:
			return nil
		}
	}
	return cur
}

// toNum 把事件侧 JSON 值转成数：protojson 对 64 位整数（tsMs/seq/startTicks…）
// 输出十进制字符串，因此数值语义必须同时接受数字与数字样字符串。
func toNum(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return n, err == nil
	}
	return 0, false
}

// equDispatch 按事件侧 JSON 值类型分派等值比较：布尔→布尔解析；两边都可数值化
// →数值比较；否则字符串比较。类型不匹配（如数字字段 vs 非数值 value）返回
// comparable=false——该条件不命中，绝不是崩溃。
func equDispatch(v any, c *compiledCond) (comparable, equal bool) {
	switch t := v.(type) {
	case bool:
		b, err := strconv.ParseBool(c.strVal)
		if err != nil {
			return false, false
		}
		return true, b == t
	case string:
		if c.numOK {
			if n, ok := toNum(t); ok {
				return true, n == c.numVal
			}
		}
		return true, t == c.strVal
	case float64:
		if !c.numOK {
			return false, false
		}
		return true, c.numVal == t
	default:
		return false, false
	}
}

// scalarHit 对单个标量求值算子；类型不满足算子需要（如 INCL 遇数字）一律 false。
func (c *compiledCond) scalarHit(v any) bool {
	switch c.kind {
	case opIncl:
		s, ok := v.(string)
		return ok && strings.Contains(s, c.strVal)
	case opStart:
		s, ok := v.(string)
		return ok && strings.HasPrefix(s, c.strVal)
	case opEnd:
		s, ok := v.(string)
		return ok && strings.HasSuffix(s, c.strVal)
	case opEqu:
		cmp, eq := equDispatch(v, c)
		return cmp && eq
	case opNeq:
		cmp, eq := equDispatch(v, c)
		return cmp && !eq
	case opRegex:
		s, ok := v.(string)
		return ok && c.re != nil && c.re.MatchString(s)
	case opMt:
		n, ok := toNum(v)
		return ok && n > c.numVal
	case opLt:
		n, ok := toNum(v)
		return ok && n < c.numVal
	}
	return false
}

// eval 对事件树求值单个条件，返回是否命中与命中描述（进 Alert.Summary）。
// 数组字段按元素求值：INCL/EQU/START/END/REGEX/MT/LT 全部逐元素，
// 元素间 any/or（默认）或 all/and；标量字段直接求值。
func (c *compiledCond) eval(root map[string]any) (bool, string) {
	v := resolvePath(root, c.path)
	if v == nil {
		return false, ""
	}
	p := strings.Join(c.path, ".")
	arr, isArr := v.([]any)
	if !isArr {
		if !c.scalarHit(v) {
			return false, ""
		}
		return true, truncRunes(fmt.Sprintf("%s=%v", p, v), 160)
	}
	if len(arr) == 0 {
		return false, ""
	}
	anyHit, allHit, first := false, true, -1
	for i, el := range arr {
		if c.scalarHit(el) {
			anyHit = true
			if first < 0 {
				first = i
			}
		} else {
			allHit = false
		}
	}
	hit := anyHit
	if c.elemAll {
		hit = allHit
	}
	if !hit {
		return false, ""
	}
	if c.elemAll || first < 0 {
		return true, p + "[*]"
	}
	return true, truncRunes(fmt.Sprintf("%s[%d]=%v", p, first, arr[first]), 160)
}

// matches 对事件树求值整条规则；返回是否命中与首个命中条件的描述。
func (r *compiledRule) matches(root map[string]any) (bool, string) {
	if r.all {
		desc := ""
		for i := range r.conds {
			hit, d := r.conds[i].eval(root)
			if !hit {
				return false, ""
			}
			if desc == "" {
				desc = d
			}
		}
		return true, desc
	}
	for i := range r.conds {
		if hit, d := r.conds[i].eval(root); hit {
			return true, d
		}
	}
	return false, ""
}

func truncRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n]) + "…"
}
