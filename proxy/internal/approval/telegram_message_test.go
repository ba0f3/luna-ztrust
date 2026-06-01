package approval

import (
	"strings"
	"testing"
)

func TestFormatApprovalMessage(t *testing.T) {
	msg := formatApprovalMessage(&Transaction{
		ID:            "tx_01",
		TargetUser:    "deploy",
		TargetIP:      "10.0.0.5",
		SourceIP:      "203.0.113.1",
		SourceUser:    "goclaw",
		ClientName:    "luna-agent",
		ClientVersion: "v0.1.0",
	})
	for _, want := range []string{
		"Target user: deploy",
		"Target host: 10.0.0.5",
		"Source IP: 203.0.113.1",
		"Source user: goclaw",
		"Client: luna-agent v0.1.0",
		"tx_01",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("missing %q in:\n%s", want, msg)
		}
	}
}
