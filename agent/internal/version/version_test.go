package version

import (
	"strings"
	"testing"
)

func TestFull(t *testing.T) {
	Version = "v1.2.3"
	Commit = "abc"
	Date = "2026-01-01"
	out := Full("luna-agent")
	for _, want := range []string{"luna-agent version v1.2.3", "commit: abc", "built: 2026-01-01"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
}
