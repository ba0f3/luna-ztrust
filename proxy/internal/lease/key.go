package lease

import (
	"fmt"
	"strings"
)

// LookupKey identifies a client session for lease reuse (excludes approver).
type LookupKey struct {
	ClientCertFP       string
	TargetUser         string
	TargetIP           string
	SourceIP           string
	HostKeyFingerprint string // local-key: binds lease to approved hosted key
}

func (k LookupKey) lookupString() string {
	return strings.Join([]string{
		k.ClientCertFP,
		k.TargetUser,
		k.TargetIP,
		k.SourceIP,
		k.HostKeyFingerprint,
	}, "|")
}

// FullKey is the complete lease identity including the approver.
type FullKey struct {
	LookupKey
	Approver string
}

func (k FullKey) String() string {
	return k.lookupString() + "|" + k.Approver
}

// NewLookupKey builds a lookup key from sign request context.
func NewLookupKey(clientCertFP, targetUser, targetIP, sourceIP, hostKeyFingerprint string) LookupKey {
	return LookupKey{
		ClientCertFP:       clientCertFP,
		TargetUser:         targetUser,
		TargetIP:           targetIP,
		SourceIP:           sourceIP,
		HostKeyFingerprint: hostKeyFingerprint,
	}
}

// NewFullKey builds a full lease key including approver identity.
func NewFullKey(lookup LookupKey, approver string) FullKey {
	return FullKey{LookupKey: lookup, Approver: approver}
}

// FormatApproverChatID normalizes Telegram chat IDs for storage.
func FormatApproverChatID(chatID int64) string {
	return fmt.Sprintf("telegram:%d", chatID)
}

// FormatApproverDeviceID normalizes enrolled mobile device IDs for lease binding.
func FormatApproverDeviceID(deviceID string) string {
	return "device:" + deviceID
}
