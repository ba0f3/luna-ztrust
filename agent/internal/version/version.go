package version

import "fmt"

// Set at link time via -ldflags (see Makefile and .goreleaser.yaml).
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns the release version (e.g. v0.2.0 or dev).
func String() string {
	return Version
}

// Full returns version, commit, and build date for CLI output.
func Full(name string) string {
	return fmt.Sprintf("%s version %s\ncommit: %s\nbuilt: %s\n", name, Version, Commit, Date)
}
