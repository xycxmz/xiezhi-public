// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R-5 回归防护：签名通道（审计高危第 1 项修复 + R8.4 导出件
// ReadRuleFiles/VerifyFiles/DirHasManifest/RequireSignedRules）此前零自动化
// 测试。本文件按 tools/sign_rules.sh 同构在 t.TempDir 内构造已签名目录：
// Go crypto/ed25519 生成密钥，公钥以 PEM PKIX 写到规则目录旁（同
// tools/gen_signing_key.sh 的 openssl pkey -pubout 产物形态），manifest 为
// {"version":"1","files":{文件名:sha256}} 并对 manifest 字节做 raw ed25519 签名。

// signedRulesDir 构造一个完整签名目录并返回规则目录路径：
// root/rules/<files> + root/signing-key.pub + .rules-manifest + .rules-signature。
func signedRulesDir(t *testing.T, root string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, "rules")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		writeFile(t, filepath.Join(dir, name), content)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// PEM SubjectPublicKeyInfo：走 pubBytesToEd25519 的生产分支（openssl 产物形态）
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "signing-key.pub"),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))

	// manifest 与 sign_rules.sh 同构：每个 *.yaml 的 sha256 hex；键序由
	// json.Marshal 排序，等价于脚本的 ls | sort。签名是对最终落盘的 manifest
	// 字节做的（同 openssl pkeyutl -sign -rawin -in .rules-manifest）。
	names, contents, err := ReadRuleFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	hashes := make(map[string]string, len(names))
	for i, name := range names {
		sum := sha256.Sum256(contents[i])
		hashes[name] = hex.EncodeToString(sum[:])
	}
	manifest, err := json.Marshal(rulesManifest{Version: "1", Files: hashes})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, manifestFile), string(manifest))
	if err := os.WriteFile(filepath.Join(dir, sigFile), ed25519.Sign(priv, manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// checkVerify 按「单次读盘、同一批字节验证」的导出件用法跑一遍验证：
// wantSub 非空时须失败且错误包含该子串，为空时须通过。
func checkVerify(t *testing.T, dir, wantSub string) {
	t.Helper()
	names, contents, err := ReadRuleFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyFiles(dir, names, contents)
	if wantSub == "" {
		if err != nil {
			t.Fatalf("期望验证通过, 却失败: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("期望验证失败(包含 %q), 却通过", wantSub)
	}
	if !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("错误应包含 %q, 得到 %q", wantSub, err.Error())
	}
}

// TestSignedRulesChannel 覆盖签名通道的正/负路径与 dev/生产两态。
func TestSignedRulesChannel(t *testing.T) {
	// 每个子测试独立签名目录，互不污染。
	newSigned := func(t *testing.T) string {
		t.Helper()
		return signedRulesDir(t, t.TempDir(), map[string]string{
			"exec.yaml": canonicalRule,
			"net.yaml":  netHighPortRule,
		})
	}

	t.Run("合法签名目录通过", func(t *testing.T) {
		dir := newSigned(t)
		if !DirHasManifest(dir) {
			t.Fatal("已签名目录 DirHasManifest 应为 true")
		}
		checkVerify(t, dir, "")
	})

	t.Run("篡改已签文件哈希", func(t *testing.T) {
		dir := newSigned(t)
		writeFile(t, filepath.Join(dir, "exec.yaml"), canonicalRule+"# tampered\n")
		checkVerify(t, dir, "hash mismatch")
	})

	t.Run("删签名文件", func(t *testing.T) {
		dir := newSigned(t)
		if err := os.Remove(filepath.Join(dir, sigFile)); err != nil {
			t.Fatal(err)
		}
		checkVerify(t, dir, "signature missing")
	})

	t.Run("加未签名文件", func(t *testing.T) {
		dir := newSigned(t)
		writeFile(t, filepath.Join(dir, "extra.yaml"), canonicalRule)
		checkVerify(t, dir, "not covered by signed manifest")
	})

	t.Run("删已签名文件", func(t *testing.T) {
		dir := newSigned(t)
		if err := os.Remove(filepath.Join(dir, "net.yaml")); err != nil {
			t.Fatal(err)
		}
		checkVerify(t, dir, "manifest file net.yaml missing")
	})

	t.Run("篡改manifest本体", func(t *testing.T) {
		// 改 manifest 内容但保留旧签名：ed25519.Verify 的 false 分支
		// （哈希核对前的第一道闸），防止验签被绕过后只靠哈希比对兜底。
		dir := newSigned(t)
		p := filepath.Join(dir, manifestFile)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, p, strings.Replace(string(b), `"version":"1"`, `"version":"9"`, 1))
		checkVerify(t, dir, "signature verification failed")
	})

	t.Run("删manifest-dev模式放行", func(t *testing.T) {
		// 显式置 0：不依赖宿主机环境变量恰好未设置
		t.Setenv("XIEZHI_RULES_REQUIRE_SIGNATURE", "0")
		dir := newSigned(t)
		if err := os.Remove(filepath.Join(dir, manifestFile)); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, sigFile)); err != nil {
			t.Fatal(err)
		}
		if DirHasManifest(dir) {
			t.Fatal("删 manifest 后 DirHasManifest 应为 false")
		}
		checkVerify(t, dir, "")
	})

	t.Run("删manifest-fail-closed", func(t *testing.T) {
		// 生产态：删掉签名件不得回退 dev 放行（防删签名即重放任意规则）
		t.Setenv("XIEZHI_RULES_REQUIRE_SIGNATURE", "1")
		dir := newSigned(t)
		if err := os.Remove(filepath.Join(dir, manifestFile)); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, sigFile)); err != nil {
			t.Fatal(err)
		}
		checkVerify(t, dir, "no signed manifest")
	})
}

// TestRequireSignedRulesEnv 钉死 fail-closed 开关的取值语义。
func TestRequireSignedRulesEnv(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{"", false},
		{"0", false},
		{"1", true},
		{"true", true},
		{"TRUE", true}, // EqualFold
		{" 1 ", true},  // TrimSpace 后置位
	} {
		t.Run("env="+tc.v, func(t *testing.T) {
			t.Setenv("XIEZHI_RULES_REQUIRE_SIGNATURE", tc.v)
			if got := RequireSignedRules(); got != tc.want {
				t.Fatalf("env=%q 期望 %v, 得到 %v", tc.v, tc.want, got)
			}
		})
	}
}
