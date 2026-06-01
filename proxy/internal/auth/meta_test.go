package auth

import "testing"

func TestNormalizeSignClientMeta(t *testing.T) {
	m := NormalizeSignClientMeta("  alice  ", "luna-agent", "v0.1.0")
	if m.SourceUser != "alice" || m.ClientName != "luna-agent" || m.ClientVersion != "v0.1.0" {
		t.Fatalf("got %+v", m)
	}
	long := string(make([]byte, 100))
	m = NormalizeSignClientMeta(long, long, long)
	if len(m.SourceUser) != maxSourceUserLen {
		t.Fatalf("source user len = %d", len(m.SourceUser))
	}
}
