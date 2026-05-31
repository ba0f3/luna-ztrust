package install

import (
	"strings"
	"testing"
)

func TestRenderAgentSystemUnit(t *testing.T) {
	body, err := RenderAgentUnit(SystemdOptions{
		BinaryPath: "/opt/luna/luna-agent",
		ConfigPath: "/etc/luna/agent.yml",
		User:       "luna",
		Group:      "luna",
		System:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/opt/luna/luna-agent",
		"User=luna",
		"RuntimeDirectory=luna",
		"WantedBy=multi-user.target",
		"Environment=LUNA_CONFIG=/etc/luna/agent.yml",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
}

func TestRenderAgentUserUnit(t *testing.T) {
	body, err := RenderAgentUnit(SystemdOptions{
		BinaryPath: "/home/me/bin/luna-agent",
		ConfigPath: "/home/me/.config/luna/agent.yml",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/home/me/bin/luna-agent",
		"Environment=LUNA_CONFIG=/home/me/.config/luna/agent.yml",
		"RuntimeDirectory=luna",
		"WantedBy=default.target",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"User=luna", "Group=luna", "multi-user.target"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("unexpected %q in user unit:\n%s", forbidden, body)
		}
	}
}

func TestDefaultAgentUserSystemdOptions(t *testing.T) {
	opts := DefaultAgentUserSystemdOptions()
	if opts.System {
		t.Fatal("expected user mode")
	}
	if !strings.Contains(opts.UnitPath, "systemd/user") {
		t.Fatalf("UnitPath = %q", opts.UnitPath)
	}
	if !strings.Contains(opts.ConfigPath, ".config/luna/agent.yml") {
		t.Fatalf("ConfigPath = %q", opts.ConfigPath)
	}
}
