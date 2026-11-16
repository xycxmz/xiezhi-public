// SPDX-License-Identifier: Apache-2.0

package llm

import "testing"

func TestParseVerdictAccepts(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    Verdict
	}{
		{
			"escalate",
			`{"state":"escalate","confidence":0.95,"reasoning":"curl 管道直接进 shell","tactic":"T1059.004"}`,
			Verdict{StateEscalate, 0.95, "curl 管道直接进 shell", "T1059.004"},
		},
		{
			"insufficient",
			`{"state":"insufficient_evidence","confidence":0.3,"reasoning":"仅一次外联，无执行链","tactic":""}`,
			Verdict{StateInsufficient, 0.3, "仅一次外联，无执行链", ""},
		},
		{
			"benign",
			`{"state":"benign_candidate","confidence":0.9,"reasoning":"yum 定时更新触发 firstseen","tactic":""}`,
			Verdict{StateBenignCand, 0.9, "yum 定时更新触发 firstseen", ""},
		},
		{
			"fenced",
			"```json\n{\"state\":\"escalate\",\"confidence\":1,\"reasoning\":\"r\",\"tactic\":\"T1059\"}\n```",
			Verdict{StateEscalate, 1, "r", "T1059"},
		},
		{
			"confidence-clamped-high",
			`{"state":"escalate","confidence":7,"reasoning":"r","tactic":""}`,
			Verdict{StateEscalate, 1, "r", ""},
		},
		{
			"confidence-clamped-low",
			`{"state":"benign_candidate","confidence":-2,"reasoning":"r","tactic":""}`,
			Verdict{StateBenignCand, 0, "r", ""},
		},
	}
	for _, c := range cases {
		got, err := parseVerdict(c.content)
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}

func TestParseVerdictRejects(t *testing.T) {
	for name, content := range map[string]string{
		"empty":         ``,
		"whitespace":    "   ",
		"not-json":      `escalate, definitely`,
		"bad-state":     `{"state":"close_alert","confidence":0.9,"reasoning":"r","tactic":""}`,
		"missing-state": `{"confidence":0.9,"reasoning":"r"}`,
		"array":         `["escalate"]`,
		"html":          `<html>escalate</html>`,
	} {
		if _, err := parseVerdict(content); err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
	}
}
