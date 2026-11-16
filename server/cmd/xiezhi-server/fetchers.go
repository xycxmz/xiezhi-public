// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	"github.com/xycxmz/xiezhi-public/server/internal/intent"
	"github.com/xycxmz/xiezhi-public/server/internal/llm"
	"github.com/xycxmz/xiezhi-public/server/internal/session"
	"github.com/xycxmz/xiezhi-public/server/internal/store"
)

// rootFinderAdapter 把 session.RootFinder 适配为 intent.RootFinder：两包的
// SessionRoot 是结构镜像的不同命名类型，接口方法签名因此不同型，须显式转换。
type rootFinderAdapter struct {
	rf session.RootFinder
}

func (a rootFinderAdapter) FindRoot(host string, pid int32) (intent.SessionRoot, bool) {
	r, ok := a.rf.FindRoot(host, pid)
	if !ok {
		return intent.SessionRoot{}, false
	}
	return intent.SessionRoot{RootPid: r.RootPid, RootTicks: r.RootTicks, RootExe: r.RootExe}, true
}

// chEventFetcher 把 store 查询适配为 llm.EventFetcher（按 agent+时间窗）。
type chEventFetcher struct {
	ch *store.CHStore
}

func (f *chEventFetcher) RecentByAgent(ctx context.Context, agentID string, sinceMs int64, limit int) ([]llm.EventSummary, error) {
	rows, err := f.ch.RecentEvents(ctx, store.Query{Agent: agentID, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]llm.EventSummary, 0, len(rows))
	for _, r := range rows {
		if r.Ts.UnixMilli() < sinceMs {
			continue
		}
		out = append(out, llm.EventSummary{TsMs: r.Ts.UnixMilli(), Type: r.EventType, Body: r.Body})
	}
	return out, nil
}

// nopSubtreeSource：session 树源暂缺接线的占位（M4 e2e 后接 session.SubtreeJSON）。
type nopSubtreeSource struct{}

func (n *nopSubtreeSource) SubtreeJSON(host string, pid int32, depth int) (string, error) {
	return "", nil
}
