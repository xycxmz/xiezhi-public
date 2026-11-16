// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileGivesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg != Default() {
		t.Fatalf("missing file must yield defaults, got %+v", cfg)
	}
}

func TestLoadParsesFullFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `
# comment line
server_addr: "10.0.0.1:9100"   # inline comment
token: 'secret-token'
agent_id_file: /tmp/xiezhi/agent_id
spool_dir: /tmp/xiezhi/spool
spool_max_mb: 50
heartbeat_interval_sec: 30
batch_max: 64
batch_flush_ms: 200
driver_enabled: true
driver_ko_dir: /data/xiezhi/ko
procpoll_interval_sec: 15
journal_path: /var/log/secure
future_key: ignored
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Config{
		ServerAddr:           "10.0.0.1:9100",
		Token:                "secret-token",
		AgentIDFile:          "/tmp/xiezhi/agent_id",
		SpoolDir:             "/tmp/xiezhi/spool",
		SpoolMaxMB:           50,
		HeartbeatIntervalSec: 30,
		BatchMax:             64,
		BatchFlushMS:         200,
		DriverEnabled:        true,
		DriverKoDir:          "/data/xiezhi/ko",
		ProcpollIntervalSec:  15,
		JournalPath:          "/var/log/secure",
	}
	if cfg != want {
		t.Fatalf("got %+v, want %+v", cfg, want)
	}
}

func TestLoadRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"nested structure":   "outer:\n  inner: 1\n",
		"line without colon": "just text\n",
		"negative int":       "batch_max: -3\n",
		"zero int":           "batch_max: 0\n",
		"non-integer":        "heartbeat_interval_sec: abc\n",
	}
	for name, body := range cases {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("%s: expected error, got nil", name)
		}
	}
}

func TestPathPrecedence(t *testing.T) {
	t.Setenv(EnvPath, "")
	if p := Path(""); p != DefaultPath {
		t.Fatalf("no flag, no env: got %s, want %s", p, DefaultPath)
	}
	t.Setenv(EnvPath, "/env/config.yaml")
	if p := Path(""); p != "/env/config.yaml" {
		t.Fatalf("env: got %s", p)
	}
	if p := Path("/flag/config.yaml"); p != "/flag/config.yaml" {
		t.Fatalf("flag must win: got %s", p)
	}
}
