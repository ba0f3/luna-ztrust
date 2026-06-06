package sign

// Request is the JSON body for POST /api/v1/ssh/sign.
type Request struct {
	PublicKey          string                `json:"public_key"`
	TargetUser         string                `json:"target_user"`
	TargetIP           string                `json:"target_ip"`
	Timestamp          int64                 `json:"timestamp"`
	PopSignature       string                `json:"pop_signature"`
	SourceUser         string                `json:"source_user,omitempty"`
	ClientName         string                `json:"client_name,omitempty"`
	ClientVersion      string                `json:"client_version,omitempty"`
	AgentSignData      string                `json:"agent_sign_data,omitempty"`
	HostKeyFingerprint string                `json:"host_key_fingerprint,omitempty"`
	SessionBinding     sessionBindingRequest `json:"session_binding,omitempty"`
}

type sessionBindingRequest struct {
	HostPublicKey []byte `json:"host_public_key"`
	SessionID     []byte `json:"session_id"`
	Signature     []byte `json:"signature"`
	Forwarding    bool   `json:"forwarding"`
}

// Response is returned from POST /api/v1/ssh/sign with status 202.
type Response struct {
	TxID string `json:"tx_id"`
}

// WaitResponse is returned from GET /api/v1/ssh/sign/{tx_id}/wait on success.
type WaitResponse struct {
	SSHCertificate string `json:"ssh_certificate"`
	SSHSignature   string `json:"ssh_signature"`
	ExpiresAt      string `json:"expires_at"`
	LeaseExpiresAt string `json:"lease_expires_at,omitempty"`
}

// ClientInfo is optional client metadata (not part of PoP).
type ClientInfo struct {
	SourceUser    string
	ClientName    string
	ClientVersion string
}

// CertRequest identifies the SSH session to certify.
type CertRequest struct {
	TargetUser string
	TargetIP   string
	Client     ClientInfo
}

// SignatureRequest identifies the SSH session for hosted-key signing.
type SignatureRequest struct {
	TargetUser         string
	TargetIP           string
	HostKeyFingerprint string
	SessionBinding     SessionBinding
	Client             ClientInfo
}

// SessionBinding proves the destination SSH host key and exchange hash.
type SessionBinding struct {
	HostPublicKey []byte
	SessionID     []byte
	Signature     []byte
	Forwarding    bool
}
