package sign

// Request is the JSON body for POST /api/v1/ssh/sign.
type Request struct {
	PublicKey    string `json:"public_key"`
	TargetUser   string `json:"target_user"`
	TargetIP     string `json:"target_ip"`
	Timestamp    int64  `json:"timestamp"`
	PopSignature string `json:"pop_signature"`
}

// Response is returned from POST /api/v1/ssh/sign with status 202.
type Response struct {
	TxID string `json:"tx_id"`
}

// WaitResponse is returned from GET /api/v1/ssh/sign/{tx_id}/wait on success.
type WaitResponse struct {
	SSHCertificate string `json:"ssh_certificate"`
	ExpiresAt      string `json:"expires_at"`
}

// CertRequest identifies the SSH session to certify.
type CertRequest struct {
	TargetUser string
	TargetIP   string
}
