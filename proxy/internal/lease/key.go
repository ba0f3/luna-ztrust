package lease

import (
	"strconv"
)

// LookupKey identifies a client session for lease reuse (excludes approver).
type LookupKey struct {
	ClientCertFP                  string
	TargetUser                    string
	TargetIP                      string
	SourceIP                      string
	HostKeyFingerprint            string // local-key: binds lease to approved hosted key
	DestinationHostKeyFingerprint string // local-key: verified SSH server host key
}

func (k LookupKey) lookupString() string {
	// ⚡ Bolt: Replace strings.Join with string concatenation to avoid heap allocation
	// of a string slice on a relatively hot path.
	return k.ClientCertFP + "|" + k.TargetUser + "|" + k.TargetIP + "|" + k.SourceIP + "|" + k.HostKeyFingerprint + "|" + k.DestinationHostKeyFingerprint
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
func NewLookupKey(clientCertFP, targetUser, targetIP, sourceIP, hostKeyFingerprint string, destinationHostKeyFingerprint ...string) LookupKey {
	destination := ""
	if len(destinationHostKeyFingerprint) > 0 {
		destination = destinationHostKeyFingerprint[0]
	}
	return LookupKey{
		ClientCertFP:                  clientCertFP,
		TargetUser:                    targetUser,
		TargetIP:                      targetIP,
		SourceIP:                      sourceIP,
		HostKeyFingerprint:            hostKeyFingerprint,
		DestinationHostKeyFingerprint: destination,
	}
}

// NewFullKey builds a full lease key including approver identity.
func NewFullKey(lookup LookupKey, approver string) FullKey {
	return FullKey{LookupKey: lookup, Approver: approver}
}

// FormatApproverChatID normalizes Telegram chat IDs for storage.
func FormatApproverChatID(chatID int64) string {
	// ⚡ Bolt: Replace fmt.Sprintf with strconv to avoid heap allocation
	return "telegram:" + strconv.FormatInt(chatID, 10)
}

// FormatApproverDeviceID normalizes enrolled mobile device IDs for lease binding.
func FormatApproverDeviceID(deviceID string) string {
	return "device:" + deviceID
}
