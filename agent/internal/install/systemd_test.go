package install

import (
	"strings"
	"testing"
)

func TestRenderAgentUnit(t *testing.T) {
	body, err := RenderAgentUnit(SystemdOptions{
		BinaryPath: "/opt/luna/luna-agent",
		ConfigPath: "/etc/luna/agent.yml",
		User:       "luna",
		Group:      "luna",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/opt/luna/luna-agent",
		"User=luna",
		"RuntimeDirectory=luna",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "LUNA_CONFIG") {
		t.Fatalf("unit should not set LUNA_CONFIG:\n%s", body)
	}
}
