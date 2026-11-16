// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// R3.5: Rules manifest signing. If .rules-manifest + .rules-signature exist
// in the rules directory, verify the ed25519 signature and every file hash
// before loading. No manifest = dev mode (WARN, load normally), unless
// XIEZHI_RULES_REQUIRE_SIGNATURE is set (production: fail closed).

var devWarnOnce sync.Once

const (
	manifestFile = ".rules-manifest"
	sigFile      = ".rules-signature"
)

type rulesManifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"` // filename -> sha256 hex
}

// verifyDirSignature checks the rules directory against its signed manifest.
// names/contents 是调用方即将解析的同一份文件字节：清单必须覆盖其中每个
// yaml（防签名后新增未签名文件），且哈希对这批字节核对——验证的字节就是
// 加载的字节，无 verify/parse 各自读盘的竞态窗口。
// Returns nil if verification passes or if no manifest exists (dev mode).
func verifyDirSignature(dir string, names []string, contents [][]byte) error {
	manifestPath := filepath.Join(dir, manifestFile)
	sigPath := filepath.Join(dir, sigFile)

	manifestBytes, err := os.ReadFile(manifestPath)
	if os.IsNotExist(err) {
		if requireSignedRules() {
			return fmt.Errorf("no signed manifest in %s (XIEZHI_RULES_REQUIRE_SIGNATURE set)", dir)
		}
		devWarnOnce.Do(func() { // R-6：intent 热更每秒调用，只告警一次
			slog.Warn("rules: no signed manifest, loading without verification (dev mode)")
		})
		return nil
	}
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	sig, err := os.ReadFile(sigPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("manifest exists but signature missing: %s", sigPath)
	}
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}

	var m rulesManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	// 公钥路径优先取 XIEZHI_RULES_PUBKEY；未设置时旁推导（规则目录旁的
	// signing-key.pub，兼容现网部署形态）。生产应通过 env 指向规则树外、
	// root 属主的只读文件——旁推导路径与被保护数据同树，能写规则目录者
	// 也能换公钥，验签即失去意义（R8.4 审计 R-4）。
	pubPath := strings.TrimSpace(os.Getenv("XIEZHI_RULES_PUBKEY"))
	if pubPath == "" {
		pubPath = filepath.Join(filepath.Dir(dir), "signing-key.pub")
	}
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read public key %s: %w", pubPath, err)
	}
	pub, ok := pubBytesToEd25519(pubBytes)
	if !ok {
		return fmt.Errorf("invalid public key format in %s", pubPath)
	}

	if !ed25519.Verify(pub, manifestBytes, sig) {
		return fmt.Errorf("manifest signature verification failed (tampered or wrong key)")
	}

	// 反向校验：目录里每个待加载 yaml 必须在清单内，否则签名后新增的
	// 未签名文件会在验签通过的情况下被加载（只防「改」不防「增」的绕过）。
	inDir := make(map[string]bool, len(names))
	for _, name := range names {
		inDir[name] = true
	}
	for name := range m.Files {
		if !inDir[name] {
			return fmt.Errorf("manifest file %s missing from %s", name, dir)
		}
	}
	for i, name := range names {
		wantHash, ok := m.Files[name]
		if !ok {
			return fmt.Errorf("file %s not covered by signed manifest (added after signing?)", name)
		}
		got := sha256.Sum256(contents[i])
		gotHex := hex.EncodeToString(got[:])
		if gotHex != wantHash {
			return fmt.Errorf("file %s hash mismatch: manifest=%s actual=%s (tampered)", name, hashPrefix(wantHash), gotHex[:12])
		}
	}

	// 成功不在此打日志：VerifyDir 被 intent 热更每秒调用，成功侧日志会
	// 每秒刷屏（首次部署实测）；规则加载路径的成功日志由 loadDir 侧打。
	return nil
}

// hashPrefix 截哈希前 12 位做错误信息；清单哈希串可短于 12（甚至为空），直接切片会越界 panic。
func hashPrefix(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// requireSignedRules 是生产 fail-closed 开关：置位后 manifest 缺失不再回退
// 无签名加载（dev mode），防止删掉签名文件即重放任意规则。
func requireSignedRules() bool {
	v := strings.TrimSpace(os.Getenv("XIEZHI_RULES_REQUIRE_SIGNATURE"))
	return v == "1" || strings.EqualFold(v, "true")
}

// pubBytesToEd25519 converts PEM or raw 32-byte public key to ed25519.PublicKey.
func pubBytesToEd25519(b []byte) (ed25519.PublicKey, bool) {
	// Try raw 32 bytes first
	if len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), true
	}
	// Try hex-encoded 64 chars
	if len(b) == 64 {
		raw, err := hex.DecodeString(string(b))
		if err == nil && len(raw) == ed25519.PublicKeySize {
			return ed25519.PublicKey(raw), true
		}
	}
	// PEM SubjectPublicKeyInfo（tools/gen_signing_key.sh 的 openssl pkey -pubout 产物）
	if block, _ := pem.Decode(b); block != nil {
		if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if pub, ok := key.(ed25519.PublicKey); ok {
				return pub, true
			}
		}
	}
	return nil, false
}

// VerifyDir 对目录做与规则加载同语义的签名验证，供 intent policy 目录
// 复用（R6.0：签名通道原本只盖 RULES_DIR，policy tamper 不设防）。
// 无 manifest 时 dev 模式放行（WARN）；XIEZHI_RULES_REQUIRE_SIGNATURE=1
// 时 fail-closed——与 loadDir 的验证路径一致。
func VerifyDir(dir string) error {
	names, contents, err := readRuleFiles(dir)
	if err != nil {
		return err
	}
	return verifyDirSignature(dir, names, contents)
}

// ReadRuleFiles/VerifyFiles/DirHasManifest/RequireSignedRules 是 intent
// policy 通道的原子件导出（R8.4 审计 R-1/R-2）：调用方单次读盘后用同一批
// 字节验证与解析，消除 VerifyDir 形态下「验证的字节≠加载的字节」的
// TOCTOU；missing 判定由 DirHasManifest/RequireSignedRules 显式支撑，
// 防止删除已签名目录内的 policy.yaml 静默旁路整层。
func ReadRuleFiles(dir string) ([]string, [][]byte, error) { return readRuleFiles(dir) }

func VerifyFiles(dir string, names []string, contents [][]byte) error {
	return verifyDirSignature(dir, names, contents)
}

func DirHasManifest(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, manifestFile))
	return err == nil
}

func RequireSignedRules() bool { return requireSignedRules() }
