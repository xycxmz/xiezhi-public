// SPDX-License-Identifier: Apache-2.0

package firstseen

import (
	"container/list"
	"sync"
	"time"
)

// ttlCache 是 LRU+TTL 双维吸收层：LRU 限内存（最近 100k 键），TTL 限窗口
// （10min）。命中即「窗口内出现过、必然不是新键」，直接省掉 PG 往返；未命中
// 才进批量管道。单 mutex：操作均 O(1)，未见争用实测前不分片。
type ttlCache struct {
	mu  sync.Mutex
	cap int
	ttl time.Duration
	now func() time.Time

	elems map[string]*list.Element
	order *list.List // 元素 *entry，front = 最近
}

type entry struct {
	key      string
	expireAt time.Time
}

func newTTLCache(capacity int, ttl time.Duration, now func() time.Time) *ttlCache {
	if now == nil {
		now = time.Now
	}
	return &ttlCache{
		cap:   capacity,
		ttl:   ttl,
		now:   now,
		elems: make(map[string]*list.Element, capacity),
		order: list.New(),
	}
}

// AddIfAbsent 报告键在窗口内是否首次出现。首次则占坑并置为最近；已存在且
// 未过期则续期并前移（调用方据此跳过入队）。
func (c *ttlCache) AddIfAbsent(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if el, ok := c.elems[key]; ok {
		e := el.Value.(*entry)
		if now.Before(e.expireAt) {
			e.expireAt = now.Add(c.ttl)
			c.order.MoveToFront(el)
			return false
		}
		c.order.Remove(el)
		delete(c.elems, key)
	}
	c.elems[key] = c.order.PushFront(&entry{key: key, expireAt: now.Add(c.ttl)})
	for c.order.Len() > c.cap {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.elems, last.Value.(*entry).key)
	}
	return true
}

// Remove 踢出键：队列满丢弃观察时调用，否则该键会被缓存压住整整一个 TTL
// 窗口，无法在下一个事件上重试。
func (c *ttlCache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.elems[key]; ok {
		c.order.Remove(el)
		delete(c.elems, key)
	}
}
