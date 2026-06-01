package auth

import "strings"

const (
	maxSourceUserLen    = 64
	maxClientNameLen    = 64
	maxClientVersionLen = 32
)

// SignClientMeta is optional metadata from the sign request body (display/audit only).
type SignClientMeta struct {
	SourceUser    string
	ClientName    string
	ClientVersion string
}

// NormalizeSignClientMeta trims and caps optional client metadata fields.
func NormalizeSignClientMeta(sourceUser, clientName, clientVersion string) SignClientMeta {
	return SignClientMeta{
		SourceUser:    trimMetaField(sourceUser, maxSourceUserLen),
		ClientName:    trimMetaField(clientName, maxClientNameLen),
		ClientVersion: trimMetaField(clientVersion, maxClientVersionLen),
	}
}

func trimMetaField(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}
	return s
}
