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
		"Environment=LUNA_CONFIG=/etc/luna/proxy.yml",
		"User=luna",
		"RuntimeDirectory=luna",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
}
