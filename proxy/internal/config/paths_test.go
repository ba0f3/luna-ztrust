package config

import (
	"path/filepath"
	"testing"
)

func TestDefaultControlSocketUsesXDGRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/tmp/xdg-runtime-test")
	got := DefaultControlSocket()
	want := filepath.Join("/tmp/xdg-runtime-test", "luna", "control.sock")
	if got != want {
		t.Fatalf("DefaultControlSocket() = %q, want %q", got, want)
	}
}

func TestDefaultControlSocketUsesHomeWhenNoXDG(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	got := DefaultControlSocket()
	want := filepath.Join(dir, ".local", "run", "luna", "control.sock")
	if got != want {
		t.Fatalf("DefaultControlSocket() = %q, want %q", got, want)
	}
}
