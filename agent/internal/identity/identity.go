// SPDX-License-Identifier: Apache-2.0

// Package identity 解析（必要时生成并持久化）agent 身份与主机事实。
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// Identity 是事件公共头富化所需的主机身份快照，进程内只读。
type Identity struct {
	AgentID    string
	Hostname   string
	BootID     string // /proc/sys/kernel/random/boot_id；不可得为空
	Kernel     string // uname -r；非 Linux 为空
	InstanceID string // ECS metadata instance-id；物理机/不可得为空（deadman 电源对账映射键）
}

// Load 返回身份。agent_id 首次生成 16 字节随机 hex 并经临时文件+rename
// 持久化；空/纯空白文件视同未生成（上次写入中途崩溃的残迹）。
func Load(agentIDFile string) (*Identity, error) {
	aid, err := loadOrCreateAgentID(agentIDFile)
	if err != nil {
		return nil, err
	}
	return &Identity{
		AgentID:    aid,
		Hostname:   hostName(),
		BootID:     bootID(),
		Kernel:     kernelRelease(),
		InstanceID: ecsInstanceID(),
	}, nil
}

func loadOrCreateAgentID(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	s := hex.EncodeToString(raw)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(s), 0o600); err != nil {
		return "", err
	}
	// Windows 上 rename 不覆盖已存在文件；此路径只在文件缺失/为空时进入，
	// 先移除空残迹再换名。
	_ = os.Remove(path)
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return s, nil
}

func hostName() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
