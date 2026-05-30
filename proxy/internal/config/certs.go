package config

import (
	"os"
	"path/filepath"
)

func defaultCertPath(name string) string {
	for _, base := range []string{
		"testdata/ca",
		filepath.Join("..", "..", "testdata", "ca"),
	} {
		p := filepath.Join(base, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Join("testdata", "ca", name)
}
