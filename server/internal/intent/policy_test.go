// SPDX-License-Identifier: Apache-2.0

package intent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const canonicalPolicy = `tags:                      # 标签->静态分
  recon_port_scan: 2.0
  download_and_execute: 5.0
  package_install: 1.0
threshold: 8.0             # 会话累加阈值
maintenance_discount: 0.4  # 维护标签衰减因子
maintenance_tags: [package_install, service_restart]
`

func TestParsePolicyCanonical(t *testing.T) {
	p, err := parsePolicy(canonicalPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.tags) != 3 || p.tags["recon_port_scan"] != 2.0 || p.tags["download_and_execute"] != 5.0 {
		t.Fatalf("tags 解析错误: %+v", p.tags)
	}
	if p.threshold != 8.0 || p.maintDiscount != 0.4 {
		t.Fatalf("标量解析错误: threshold=%v discount=%v", p.threshold, p.maintDiscount)
	}
	if len(p.maintTags) != 2 {
		t.Fatalf("maintenance_tags 解析错误: %+v", p.maintTags)
	}
	if _, ok := p.maintTags["service_restart"]; !ok {
		t.Fatal("maintenance_tags 缺 service_restart")
	}
}

func TestParsePolicyDefaultsAndForms(t *testing.T) {
	p, err := parsePolicy("tags:\n  a: 1.0\nthreshold: 3.0\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.maintDiscount != 1.0 || len(p.maintTags) != 0 {
		t.Fatalf("maintenance 缺省应为 1.0/空: %+v", p)
	}

	block := `tags:
  a: 1.0
threshold: 3.0
maintenance_tags:
  - a
  - 'b'
maintenance_discount: 0.5
`
	p2, err := parsePolicy(block)
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.maintTags) != 2 || p2.maintDiscount != 0.5 {
		t.Fatalf("块式 maintenance_tags 解析错误: %+v", p2)
	}
}

func TestParsePolicyNegativeScore(t *testing.T) {
	p, err := parsePolicy("tags:\n  benign_admin: -1.0\n  attack: 5.0\nthreshold: 3.0\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.tags["benign_admin"] != -1.0 {
		t.Fatalf("负分（良性抵扣）应可解析: %+v", p.tags)
	}
}

func TestParsePolicyRejects(t *testing.T) {
	cases := []struct {
		name, src, wantErr string
	}{
		{"未知顶层键", "tags:\n  a: 1.0\nthreshold: 3\nbogus: 1\n", "未知顶层键"},
		{"Tab 缩进", "tags:\n\ta: 1.0\nthreshold: 3\n", "Tab"},
		{"标签重复", "tags:\n  a: 1.0\n  a: 2.0\nthreshold: 3\n", "重复"},
		{"顶层键重复", "tags:\n  a: 1.0\nthreshold: 3\nthreshold: 4\n", "重复"},
		{"非浮点", "tags:\n  a: high\nthreshold: 3\n", "非浮点数"},
		{"分值越界", "tags:\n  a: 10.5\nthreshold: 3\n", "越界"},
		{"分值负越界", "tags:\n  a: -1.5\nthreshold: 3\n", "越界"},
		{"threshold 缺失", "tags:\n  a: 1.0\n", "threshold"},
		{"threshold 非正", "tags:\n  a: 1.0\nthreshold: 0\n", "非正"},
		{"tags 缺失", "threshold: 3\n", "tags"},
		{"tags 空块", "tags:\nthreshold: 3\n", "tags 块为空"},
		{"discount 大于 1", "tags:\n  a: 1.0\nthreshold: 3\nmaintenance_discount: 1.2\n", "(0,1]"},
		{"流式列表未闭合", "tags:\n  a: 1.0\nthreshold: 3\nmaintenance_tags: [a, b\n", "流式列表"},
		{"二层嵌套", "tags:\n  a: 1.0\n    b: 2.0\nthreshold: 3\n", "二层嵌套"},
		{"非法标签名", "tags:\n  a b: 1.0\nthreshold: 3\n", "非法标签名"},
		{"值位置嵌套映射", "tags:\n  a: 1.0\nthreshold: x: y\n", "非浮点数"},
		{"maintenance 块非列表", "tags:\n  a: 1.0\nthreshold: 3\nmaintenance_tags:\n  a: 1\n", "期待列表项"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePolicy(tc.src)
			if err == nil {
				t.Fatalf("应报错，得到 nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误信息应含 %q，得到 %v", tc.wantErr, err)
			}
		})
	}
}

func TestLoadPolicyMissingAndVersion(t *testing.T) {
	dir := t.TempDir()
	pol, missing, err := loadPolicy(filepath.Join(dir, "nope.yaml"))
	if err != nil || !missing || pol != nil {
		t.Fatalf("缺失文件应 (nil,true,nil)，得到 (%v,%v,%v)", pol, missing, err)
	}
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(canonicalPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, missing, err = loadPolicy(path)
	if err != nil || missing || pol == nil {
		t.Fatalf("合法文件应解析成功: pol=%v missing=%v err=%v", pol, missing, err)
	}
	if len(pol.version) != 12 {
		t.Fatalf("version 应为 12 位哈希，得到 %q", pol.version)
	}
	pol2, _, err := loadPolicy(path)
	if err != nil || pol2.version != pol.version {
		t.Fatalf("同内容文件 version 应一致: %q vs %q", pol.version, pol2.version)
	}
}
