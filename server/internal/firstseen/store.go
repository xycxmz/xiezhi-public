// SPDX-License-Identifier: Apache-2.0

package firstseen

import "context"

// Store 是 first_seen 表的持久化边界。生产实现是
// server/internal/firstseen/pgstore（pgx，库表 first_seen）；测试用内存 fake，
// 不引真 PG。
type Store interface {
	// Upsert 批量写入：已存在键更新 last_ts/hit_count，不存在键插入。
	// 返回 obs 中「全局首次出现」键的下标——权威判定在 PG 层
	//（INSERT ... ON CONFLICT ... RETURNING xmax=0 技巧，见 pgstore 注释）。
	Upsert(ctx context.Context, obs []Obs) ([]int, error)
	Close() error
}
