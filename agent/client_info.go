package agent

import (
	"os"
	"os/user"

	"github.com/ba0f3/luna-ztrust/agent/internal/version"
	"github.com/ba0f3/luna-ztrust/sdk"
)

const clientName = "luna-agent"

// DefaultClientInfo returns SDK client metadata for sign requests from this agent.
func DefaultClientInfo() sdk.ClientInfo {
	sourceUser := os.Getenv("USER")
	if u, err := user.Current(); err == nil && u.Username != "" {
		sourceUser = u.Username
	}
	return sdk.ClientInfo{
		SourceUser:    sourceUser,
		ClientName:    clientName,
		ClientVersion: version.String(),
	}
}
