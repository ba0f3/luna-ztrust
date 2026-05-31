package install

import (
	"strings"
	"testing"
)

func TestRenderProxyUnit(t *testing.T) {
	body, err := RenderProxyUnit(SystemdOptions{
		BinaryPath: "/opt/luna/luna-proxy",
		ConfigPath: "/etc/luna/proxy.yml",
		User:       "luna",
		Group:      "luna",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/opt/luna/luna-proxy serve",
		"User=luna",
		"RuntimeDirectory=luna",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "LUNA_CONFIG") {
		t.Fatalf("unit should not set LUNA_CONFIG (optional config merge):\n%s", body)
	}
}
