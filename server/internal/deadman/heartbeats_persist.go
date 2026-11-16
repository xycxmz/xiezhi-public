// SPDX-License-Identifier: Apache-2.0

// heartbeats_persist.go 是心跳视图的 PG 持久化（M4）：消除 server 重启后的
// dead-man 盲窗——重启不回灌则 Heartbeats 清零，所有 agent 要等下一跳才回到
// 视野，期间 staleness 判定失真。AttachPersist 启动时同步回灌、运行期定时
// 全量快照 upsert（幂等），main 在起看门狗前调用。
//
// 用法：stop, err := deadman.AttachPersist(beats, dsn, 30*time.Second)；
// 失败可降级运行（仅丢持久化），stop 在关停序列里与看门狗一起调。
package deadman

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/xycxmz/xiezhi-public/server/internal/ingest"
)

const hbDDL = `CREATE TABLE IF NOT EXISTS heartbeat_state (
	agent_id    TEXT PRIMARY KEY,
	hostname    TEXT NOT NULL DEFAULT '',
	instance_id TEXT NOT NULL DEFAULT '',
	last_ms     BIGINT NOT NULL
)`

// hbStore 是心跳持久化边界：生产 pgHBStore（pgx stdlib），测试 fake（不引真库）。
type hbStore interface {
	UpsertBeats(ctx context.Context, beats []ingest.Beat) error
	LoadBeats(ctx context.Context) ([]ingest.Beat, error)
	Close() error
}

type pgHBStore struct{ db *sql.DB }

func openHBStore(dsn string) (*pgHBStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("deadman hb persist open: %w", err)
	}
	db.SetMaxOpenConns(2)
	if _, err := db.Exec(hbDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("deadman hb persist ddl: %w", err)
	}
	return &pgHBStore{db: db}, nil
}

// UpsertBeats 全量快照幂等写：重放任意次收敛同一终态；last_ms 取 GREATEST
// 保证时间戳只前进，陈旧快照迟到也不回拨 PG 侧状态。
func (s *pgHBStore) UpsertBeats(ctx context.Context, beats []ingest.Beat) error {
	if len(beats) == 0 {
		return nil
	}
	var sb strings.Builder
	args := make([]any, 0, len(beats)*4)
	sb.WriteString("INSERT INTO heartbeat_state (agent_id, hostname, instance_id, last_ms) VALUES ")
	for i, b := range beats {
		if i > 0 {
			sb.WriteByte(',')
		}
		o := i * 4
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d)", o+1, o+2, o+3, o+4)
		args = append(args, b.AgentID, b.Hostname, b.InstanceID, b.LastMs)
	}
	sb.WriteString(" ON CONFLICT (agent_id) DO UPDATE SET hostname = EXCLUDED.hostname, instance_id = EXCLUDED.instance_id, last_ms = GREATEST(heartbeat_state.last_ms, EXCLUDED.last_ms)")
	_, err := s.db.ExecContext(ctx, sb.String(), args...)
	return err
}

func (s *pgHBStore) LoadBeats(ctx context.Context) ([]ingest.Beat, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT agent_id, hostname, instance_id, last_ms FROM heartbeat_state ORDER BY agent_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ingest.Beat
	for rows.Next() {
		var b ingest.Beat
		if err := rows.Scan(&b.AgentID, &b.Hostname, &b.InstanceID, &b.LastMs); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *pgHBStore) Close() error { return s.db.Close() }

// AttachPersist 打开 PG、同步回灌心跳视图、起定时快照循环。回灌或建表失败
// 返回 err（调用方可降级为不持久化运行）；stop 幂等，先做最后一次快照再关库。
func AttachPersist(hb *ingest.Heartbeats, dsn string, interval time.Duration) (stop func(), err error) {
	st, err := openHBStore(dsn)
	if err != nil {
		return nil, err
	}
	stop, err = attachPersist(hb, st, interval)
	if err != nil {
		st.Close()
		return nil, err
	}
	return stop, nil
}

// attachPersist 是注入 store 的可测内核：LoadBeats → Record 回灌（Record 只
// 接受更晚时间戳、空 instance 不覆盖，PG 行乱序/滞后不破坏内存视图；启动时
// 内存为空所以全收），然后每 interval 全量 upsert 一次。
func attachPersist(hb *ingest.Heartbeats, st hbStore, interval time.Duration) (stop func(), err error) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := loadInto(ctx, hb, st); err != nil {
		cancel()
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				// 收尾快照：停机前刚到的心跳不丢一个 interval 的状态。
				// 用独立短超时 ctx——循环 ctx 已取消。
				fctx, fcancel := context.WithTimeout(context.Background(), 3*time.Second)
				if err := st.UpsertBeats(fctx, hb.Snapshot()); err != nil {
					slog.Warn("deadman heartbeat persist final save failed", "err", err)
				}
				fcancel()
				return
			case <-t.C:
				if err := st.UpsertBeats(ctx, hb.Snapshot()); err != nil {
					slog.Warn("deadman heartbeat persist upsert failed", "err", err)
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
			if err := st.Close(); err != nil {
				slog.Warn("deadman heartbeat persist close", "err", err)
			}
		})
	}, nil
}

func loadInto(ctx context.Context, hb *ingest.Heartbeats, st hbStore) error {
	beats, err := st.LoadBeats(ctx)
	if err != nil {
		return err
	}
	for _, b := range beats {
		hb.Record(b.AgentID, b.Hostname, b.InstanceID, b.LastMs)
	}
	if len(beats) > 0 {
		slog.Info("deadman heartbeats restored from pg", "agents", len(beats))
	}
	return nil
}
