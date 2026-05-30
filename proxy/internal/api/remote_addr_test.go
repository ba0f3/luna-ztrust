package api

import "testing"

func TestClientIPFromRemoteAddr(t *testing.T) {
	if got := clientIPFromRemoteAddr("203.0.113.1:54321"); got != "203.0.113.1" {
		t.Fatalf("got %q", got)
	}
	if got := clientIPFromRemoteAddr("not-an-ip:port:extra"); got != "" {
		t.Fatalf("unparseable addr should fail closed, got %q", got)
	}
}
