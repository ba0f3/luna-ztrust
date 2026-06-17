package auth

import (
	"errors"
	"strings"
)

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

var ErrInvalidDisplayField = errors.New("display field contains control characters")

// ValidateDisplayFields rejects control characters that can spoof approval UI.
func ValidateDisplayFields(targetUser, targetIP string, meta SignClientMeta) error {
	// ⚡ Bolt: Expand loop into direct checks to avoid []string allocation on the hot path
	if err := checkDisplayField(targetUser); err != nil {
		return err
	}
	if err := checkDisplayField(targetIP); err != nil {
		return err
	}
	if err := checkDisplayField(meta.SourceUser); err != nil {
		return err
	}
	if err := checkDisplayField(meta.ClientName); err != nil {
		return err
	}
	if err := checkDisplayField(meta.ClientVersion); err != nil {
		return err
	}
	return nil
}

func checkDisplayField(field string) error {
	for _, r := range field {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidDisplayField
		}
	}
	return nil
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
