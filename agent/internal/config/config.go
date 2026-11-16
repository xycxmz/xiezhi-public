// SPDX-License-Identifier: Apache-2.0

// Package config 加载 xiezhi-agent 的扁平 YAML 配置。
//
// 仓库 go.mod 冻结于 M0（仅 grpc/protobuf），未携带 YAML 解析依赖，
// 因此这里自带一个只覆盖本项目配置子集（一层 `key: value` 标量）的
// 解析器。嵌套结构直接报错而不是静默忽略：半解析的配置比启动失败
// 更危险。
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	// DefaultPath 默认配置文件路径。
	DefaultPath = "/etc/xiezhi-agent/config.yaml"
	// DefaultAgentIDFile agent 身份持久化文件。
	DefaultAgentIDFile = "/var/lib/xiezhi-agent/agent_id"
	// DefaultSpoolDir 断线暂存目录。
	DefaultSpoolDir = "/var/lib/xiezhi-agent/spool"
	// DefaultDriverKoDir LKM ko 目录。
	DefaultDriverKoDir = "/var/lib/xiezhi-agent/ko"
	// EnvPath 配置路径的环境变量覆盖。
	EnvPath = "XIEZHI_AGENT_CONFIG"
)

// Config 是 agent 的全部配置。字段与 config.yaml 键一一对应（snake_case）。
type Config struct {
	ServerAddr           string
	Token                string
	AgentIDFile          string
	SpoolDir             string
	SpoolMaxMB           int
	HeartbeatIntervalSec int
	BatchMax             int
	BatchFlushMS         int
	DriverEnabled        bool   // LKM 采集线开关（eBPF 线自动探测，无需开关）
	DriverKoDir          string // LKM ko 目录，文件名 xiezhi_driver-<uname -r>.ko
	TLSCa                string // mTLS：三路径齐备启用（server CA）
	TLSCert              string // mTLS：agent 客户端证书
	TLSKey               string // mTLS：agent 客户端私钥
	ProcpollIntervalSec  int    // /proc 对账轮询周期
	JournalPath          string // 认证日志路径（Debian/Ubuntu auth.log；RHEL 系 /var/log/secure）
}

// Default 返回全默认值配置。
func Default() Config {
	return Config{
		AgentIDFile:          DefaultAgentIDFile,
		SpoolDir:             DefaultSpoolDir,
		DriverKoDir:          DefaultDriverKoDir,
		SpoolMaxMB:           200,
		HeartbeatIntervalSec: 60,
		BatchMax:             100,
		BatchFlushMS:         1000,
		ProcpollIntervalSec:  10,
		JournalPath:          "/var/log/auth.log",
	}
}

// Path 解析配置文件路径：flag 显式指定 > XIEZHI_AGENT_CONFIG > 默认路径。
func Path(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv(EnvPath); env != "" {
		return env
	}
	return DefaultPath
}

// Load 读取并解析配置。文件不存在时返回全默认值（零值配置语义）；
// 数值键必须为正整数，负值/非整数/非正数为配置错误。
// 未知键忽略（向前兼容新增字段）。
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	kv, err := parseFlatYAML(data)
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.apply(kv); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func parseFlatYAML(data []byte) (map[string]string, error) {
	out := make(map[string]string)
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t") {
			return nil, fmt.Errorf("line %d: nested structures are not supported", i+1)
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("line %d: expected `key: value`", i+1)
		}
		out[strings.TrimSpace(key)] = scalar(strings.TrimSpace(val))
	}
	return out, nil
}

// scalar 先去行内注释，再按成对引号剥壳。
func scalar(v string) string {
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

func (c *Config) apply(kv map[string]string) error {
	for k, v := range kv {
		var err error
		switch k {
		case "server_addr":
			c.ServerAddr = v
		case "token":
			c.Token = v
		case "agent_id_file":
			if v != "" {
				c.AgentIDFile = v
			}
		case "spool_dir":
			if v != "" {
				c.SpoolDir = v
			}
		case "spool_max_mb":
			c.SpoolMaxMB, err = positiveInt(k, v)
		case "heartbeat_interval_sec":
			c.HeartbeatIntervalSec, err = positiveInt(k, v)
		case "batch_max":
			c.BatchMax, err = positiveInt(k, v)
		case "batch_flush_ms":
			c.BatchFlushMS, err = positiveInt(k, v)
		case "driver_enabled":
			c.DriverEnabled, err = boolValue(k, v)
		case "driver_ko_dir":
			if v != "" {
				c.DriverKoDir = v
			}
		case "tls_ca":
			c.TLSCa = v
		case "tls_cert":
			c.TLSCert = v
		case "tls_key":
			c.TLSKey = v
		case "procpoll_interval_sec":
			c.ProcpollIntervalSec, err = positiveInt(k, v)
		case "journal_path":
			if v != "" {
				c.JournalPath = v
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func positiveInt(key, v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not an integer", key, v)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s: must be positive, got %d", key, n)
	}
	return n, nil
}

func boolValue(key, v string) (bool, error) {
	switch strings.ToLower(v) {
	case "true", "yes", "1":
		return true, nil
	case "false", "no", "0", "":
		return false, nil
	}
	return false, fmt.Errorf("%s: expect bool, got %q", key, v)
}
