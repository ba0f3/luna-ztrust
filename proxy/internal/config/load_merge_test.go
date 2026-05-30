package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

func TestLoadMergesConfigFilesInOrder(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("LUNA_CONFIG", "")

	dir := t.TempDir()
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	userCfg := filepath.Join(dir, ".config", "luna")
	if err := os.MkdirAll(userCfg, 0o755); err != nil {
		t.Fatal(err)
	}
	etcCfg := filepath.Join(dir, "etc", "luna")
	if err := os.MkdirAll(etcCfg, 0o755); err != nil {
		t.Fatal(err)
	}

	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(filepath.Join(dir, "proxy.yml"), "listen_addr: \":1111\"\n")
	write(filepath.Join(userCfg, "proxy.yml"), "listen_addr: \":2222\"\n")
	write(filepath.Join(etcCfg, "proxy.yml"), "listen_addr: \":3333\"\n")

	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv("HOME", dir)

	// Patch /etc/luna by placing etc/luna under dir and using a relative path trick.
	// proxyConfigPaths uses /etc/luna fixed — test merge of cwd + user only.
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":2222" {
		t.Fatalf("ListenAddr = %q, want :2222 (user config overrides cwd)", cfg.ListenAddr)
	}
}
