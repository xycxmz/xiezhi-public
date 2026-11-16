// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procpoll

import (
	"reflect"
	"testing"
)

// diff 表驱动：appeared 的判定口径 = pid 新出现，或同 pid 但 start_ticks 变化
// （PID 复用=旧进程已死，新进程按 appeared 上报）。
func TestDiffAppeared(t *testing.T) {
	cases := []struct {
		name string
		prev snapshot
		cur  snapshot
		want []uint32
	}{
		{
			name: "both empty",
			prev: snapshot{},
			cur:  snapshot{},
			want: nil,
		},
		{
			name: "first round is all appeared (baseline)",
			prev: snapshot{},
			cur:  snapshot{1: {Pid: 1, StartTicks: 10}, 100: {Pid: 100, StartTicks: 20}},
			want: []uint32{1, 100},
		},
		{
			name: "steady state no diff",
			prev: snapshot{1: {Pid: 1, StartTicks: 10}},
			cur:  snapshot{1: {Pid: 1, StartTicks: 10}},
			want: nil,
		},
		{
			name: "new pid appeared, gone ignored",
			prev: snapshot{1: {Pid: 1, StartTicks: 10}, 2: {Pid: 2, StartTicks: 5}},
			cur:  snapshot{1: {Pid: 1, StartTicks: 10}, 999: {Pid: 999, StartTicks: 7}},
			want: []uint32{999},
		},
		{
			name: "pid reuse counts as appeared",
			prev: snapshot{42: {Pid: 42, StartTicks: 111}},
			cur:  snapshot{42: {Pid: 42, StartTicks: 222}},
			want: []uint32{42},
		},
		{
			name: "result sorted numerically",
			prev: snapshot{},
			cur:  snapshot{300: {Pid: 300}, 40: {Pid: 40}, 5: {Pid: 5}},
			want: []uint32{5, 40, 300},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := diffAppeared(tc.prev, tc.cur)
			if len(tc.want) == 0 {
				if len(got) != 0 {
					t.Errorf("diffAppeared = %v, want empty", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("diffAppeared = %v, want %v", got, tc.want)
			}
		})
	}
}
