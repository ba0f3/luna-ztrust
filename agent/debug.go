package agent

import (
	"os"
	"strings"
)

// DebugEnabled reports whether verbose agent logging is enabled.
func DebugEnabled() bool {
	v := strings.TrimSpace(os.Getenv("LUNA_AGENT_DEBUG"))
	return v == "1" || strings.EqualFold(v, "true")
}
