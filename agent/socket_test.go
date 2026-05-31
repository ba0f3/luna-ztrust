package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveSocketPath_Explicit(t *testing.T) {
	const path = "/tmp/luna-agent-test.sock"
	if got := ResolveSocketPath(path); got != path {
		t.Fatalf("got %q", got)
	}
}

func TestResolveSocketPath_NonRootWithoutRunLuna(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipped as root")
	}
	if productionSocketDirUsable("/run/luna") {
		t.Skip("/run/luna is writable in this environment")
	}
	got := ResolveSocketPath("/run/luna/agent.sock")
	want := UserSocketPath()
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestEnsureSocketDir_CreatesParent(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "luna", "agent.sock")
	if err := EnsureSocketDir(socket); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Dir(socket))
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("expected directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestEnsureSocketDir_ExistingDir(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "agent.sock")
	if err := EnsureSocketDir(socket); err != nil {
		t.Fatal(err)
	}
}
