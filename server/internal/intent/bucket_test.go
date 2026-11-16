// SPDX-License-Identifier: Apache-2.0

package intent

import (
	"testing"
	"time"
)

func testPolicy(tags map[string]float64, threshold, discount float64, maint ...string) *policy {
	p := &policy{tags: tags, threshold: threshold, maintDiscount: discount, maintTags: map[string]struct{}{}}
	for _, m := range maint {
		p.maintTags[m] = struct{}{}
	}
	return p
}

func lbl(tags ...string) []Label {
	out := make([]Label, 0, len(tags))
	for _, t := range tags {
		out = append(out, Label{Tag: t, Score: 1.0})
	}
	return out
}

func TestBucketCrossOnce(t *testing.T) {
	pol := testPolicy(map[string]float64{"a": 5.0, "b": 5.0}, 8.0, 1.0)
	s := newBucketStore(10 * time.Minute)
	base := int64(1731400000000)

	if r := s.add("h", 0, 0, base, lbl("a"), pol); r.crossed || r.total != 5.0 {
		t.Fatalf("首次 5 分不应跨越: %+v", r)
	}
	r := s.add("h", 0, 0, base+1, lbl("b"), pol)
	if !r.crossed || r.total != 10.0 {
		t.Fatalf("累计 10 分应首次跨越: %+v", r)
	}
	if r := s.add("h", 0, 0, base+2, lbl("a"), pol); r.crossed || r.total != 15.0 {
		t.Fatalf("跨越后继续累计但不再告警: %+v", r)
	}

	if r := s.add("h", 1000, 0, base, lbl("a", "b"), pol); !r.crossed {
		t.Fatal("不同 uid 是独立桶，应各自跨越")
	}
}

func TestBucketWindowReset(t *testing.T) {
	pol := testPolicy(map[string]float64{"a": 5.0}, 8.0, 1.0)
	s := newBucketStore(10 * time.Minute)
	base := int64(1731400000000)

	if r := s.add("h", 0, 0, base, lbl("a"), pol); r.crossed {
		t.Fatal("5 分不跨越")
	}
	if r := s.add("h", 0, 0, base+1000, lbl("a"), pol); !r.crossed {
		t.Fatal("10 分应跨越")
	}
	// 11 分钟后旧条目滑出窗口，桶自然重置，可再次跨越。
	if r := s.add("h", 0, 0, base+11*time.Minute.Milliseconds(), lbl("a"), pol); r.crossed || r.total != 5.0 {
		t.Fatalf("滑空后应回到 5 分未跨越: %+v", r)
	}
	if r := s.add("h", 0, 0, base+11*time.Minute.Milliseconds()+1000, lbl("a"), pol); !r.crossed {
		t.Fatal("重置后再次到 10 分应再次跨越")
	}
}

func TestMaintenanceDiscount(t *testing.T) {
	tags := map[string]float64{"package_install": 2.0, "download_and_execute": 5.0}
	pol := testPolicy(tags, 8.0, 0.4, "package_install")
	s := newBucketStore(10 * time.Minute)
	base := int64(1731400000000)

	// 维护占比 6/11 > 50%：11 * 0.4 = 4.4 < 8，不告警。
	for i := 0; i < 3; i++ {
		s.add("h", 0, 0, base+int64(i), lbl("package_install"), pol)
	}
	if r := s.add("h", 0, 0, base+3, lbl("download_and_execute"), pol); r.crossed || !r.discounted || r.total != 4.4 {
		t.Fatalf("维护占比过半应衰减到 4.4 不跨越: %+v", r)
	}

	// 独立桶：维护占比 2/12 < 50%，12 分全额跨越。
	s.add("h", 7, 0, base, lbl("package_install"), pol)
	if r := s.add("h", 7, 0, base+1, lbl("download_and_execute"), pol); r.crossed {
		t.Fatal("7 分不应跨越")
	}
	if r := s.add("h", 7, 0, base+2, lbl("download_and_execute"), pol); !r.crossed || r.discounted || r.total != 12.0 {
		t.Fatalf("维护占比未过半不衰减，12 分应全额跨越: %+v", r)
	}
}

func TestPolicyRescoreOnSwap(t *testing.T) {
	polA := testPolicy(map[string]float64{"a": 5.0}, 12.0, 1.0)
	s := newBucketStore(10 * time.Minute)
	base := int64(1731400000000)

	s.add("h", 0, 0, base, lbl("a"), polA)
	if r := s.add("h", 0, 0, base+1, lbl("a"), polA); r.crossed {
		t.Fatal("5+5=10 < 12 不跨越")
	}
	// 策略热更：同标签分值升到 6，窗口内旧条目按新分值重算（6*3=18 ≥ 12）。
	polB := testPolicy(map[string]float64{"a": 6.0}, 12.0, 1.0)
	if r := s.add("h", 0, 0, base+2, lbl("a"), polB); !r.crossed || r.total != 18.0 {
		t.Fatalf("热更后旧条目应重算为 18 并跨越: %+v", r)
	}
}

func TestBucketSweep(t *testing.T) {
	pol := testPolicy(map[string]float64{"a": 1.0}, 99.0, 1.0)
	s := newBucketStore(10 * time.Minute)
	base := int64(1731400000000)

	s.add("h", 0, 0, base, lbl("a"), pol)
	s.add("stale", 0, 0, base, lbl("a"), pol)
	if s.count() != 2 {
		t.Fatalf("应有 2 桶: %d", s.count())
	}
	s.sweep(base + 11*time.Minute.Milliseconds())
	if s.count() != 0 {
		t.Fatalf("整窗静默的桶应被清掉: %d", s.count())
	}
}
