// SPDX-License-Identifier: Apache-2.0

package intent

import (
	"sync"
	"time"
)

// bucketKey: R4.3 upgraded to support session tree roots.
// When rootPid is non-zero, bucket keys on (host, rootPid) instead of (host, uid).
type bucketKey struct {
	host    string
	uid     uint32
	rootPid int32 // 0 = legacy (host, uid) mode
}

type hitEntry struct {
	tsMs   int64
	labels []Label
}

type bucket struct {
	hits    []hitEntry
	alerted bool
}

type addResult struct {
	total      float64 // 折后总分（可能已乘维护衰减）
	crossed    bool    // 本次追加导致首次跨越阈值
	discounted bool
	tagPts     map[string]float64 // 窗口内逐标签累计（告警摘要用）
}

type bucketStore struct {
	mu      sync.Mutex
	window  time.Duration
	buckets map[bucketKey]*bucket
}

func newBucketStore(window time.Duration) *bucketStore {
	return &bucketStore{window: window, buckets: make(map[bucketKey]*bucket, 16)}
}

// add 追加一次命中并重算全桶。跨越语义：桶从未告警且折后总分 ≥ 阈值时
// crossed=true（只此一次）；窗口滑空后 alerted 重置，可再次跨越。
func (s *bucketStore) add(host string, uid uint32, rootPid int32, tsMs int64, labels []Label, pol *policy) addResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	// root 模式桶键=(host, rootPid)（R4.3 声明语义）：同一会话树内 uid 切换
	// （sudo/setuid 提权链）不得分桶，否则分数分散、漏判或双告警。
	k := bucketKey{host: host, rootPid: rootPid}
	if rootPid == 0 {
		k.uid = uid // legacy 模式维持 (host, uid)
	}
	b := s.buckets[k]
	if b == nil {
		b = &bucket{}
		s.buckets[k] = b
	}
	b.prune(tsMs, s.window)
	b.hits = append(b.hits, hitEntry{tsMs: tsMs, labels: labels})
	total, maint, tagPts := scoreBucket(b, pol)
	discounted := total > 0 && maint/total > 0.5
	if discounted {
		total *= pol.maintDiscount
	}
	if !b.alerted && total >= pol.threshold {
		b.alerted = true
		return addResult{total: total, crossed: true, discounted: discounted, tagPts: tagPts}
	}
	return addResult{total: total, discounted: discounted, tagPts: tagPts}
}

// prune 丢弃窗口外条目；滑空即重置告警状态（「首次跨越只告警一次」的
// 自然复位路径）。
func (b *bucket) prune(nowMs int64, window time.Duration) {
	cut := nowMs - window.Milliseconds()
	keep := b.hits[:0]
	for _, e := range b.hits {
		if e.tsMs > cut {
			keep = append(keep, e)
		}
	}
	b.hits = keep
	if len(b.hits) == 0 {
		b.alerted = false
	}
}

// scoreBucket 返回（总分, 维护标签贡献, 逐标签累计）。分值 = 策略分 × 标注置信度。
func scoreBucket(b *bucket, pol *policy) (total, maint float64, tagPts map[string]float64) {
	tagPts = make(map[string]float64, 8)
	for _, e := range b.hits {
		for _, l := range e.labels {
			pts := pol.tags[l.Tag] * l.Score
			total += pts
			tagPts[l.Tag] += pts
			if _, ok := pol.maintTags[l.Tag]; ok {
				maint += pts
			}
		}
	}
	return total, maint, tagPts
}

// sweep 清掉整窗静默的桶，防 (host, uid) 笛卡尔积无限增长。
func (s *bucketStore) sweep(nowMs int64) {
	cut := nowMs - s.window.Milliseconds()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, b := range s.buckets {
		stale := true
		for _, e := range b.hits {
			if e.tsMs > cut {
				stale = false
				break
			}
		}
		if stale {
			delete(s.buckets, k)
		}
	}
}

func (s *bucketStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buckets)
}
