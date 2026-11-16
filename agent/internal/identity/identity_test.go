// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAgentIDGeneratedThenReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent_id")
	id1, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(id1.AgentID) != 32 {
		t.Fatalf("agent_id = %q, want 32 hex chars", id1.AgentID)
	}
	id2, err := Load(path)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if id2.AgentID != id1.AgentID {
		t.Fatalf("agent_id not reused: %q vs %q", id1.AgentID, id2.AgentID)
	}
}

func TestAgentIDEmptyFileRegenerated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent_id")
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if id.AgentID == "" {
		t.Fatal("empty file must regenerate agent_id")
	}
}

func TestAgentIDWhitespaceTrimmed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent_id")
	if err := os.WriteFile(path, []byte("fixed-id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if id.AgentID != "fixed-id" {
		t.Fatalf("agent_id = %q, want fixed-id", id.AgentID)
	}
}
