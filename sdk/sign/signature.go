package sign

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// RequestSignature obtains a signature for signData from luna-proxy in local-key mode.
func (c *Client) RequestSignature(ctx context.Context, req SignatureRequest, signData []byte) (*ssh.Signature, error) {
	if req.TargetUser == "" || req.TargetIP == "" {
		return nil, fmt.Errorf("TargetUser and TargetIP are required")
	}
	if len(signData) == 0 {
		return nil, fmt.Errorf("signData is required")
	}
	// ⚡ Bolt: Use direct if-statements instead of a temporary slice to avoid slice allocation and loop overhead.
	sessionBindingFields := 0
	if len(req.SessionBinding.HostPublicKey) > 0 {
		sessionBindingFields++
	}
	if len(req.SessionBinding.SessionID) > 0 {
		sessionBindingFields++
	}
	if len(req.SessionBinding.Signature) > 0 {
		sessionBindingFields++
	}
	if sessionBindingFields != 0 && sessionBindingFields != 3 {
		return nil, fmt.Errorf("SessionBinding is incomplete")
	}
	hasSessionBinding := sessionBindingFields == 3
	if !hasSessionBinding && len(req.DestinationHostPublicKey) == 0 {
		return nil, fmt.Errorf("SessionBinding or DestinationHostPublicKey is required")
	}
	if hasSessionBinding && len(req.DestinationHostPublicKey) > 0 {
		return nil, fmt.Errorf("SessionBinding and DestinationHostPublicKey are mutually exclusive")
	}
	if req.SessionBinding.Forwarding {
		return nil, fmt.Errorf("forwarded SessionBinding is not allowed")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ssh public key: %w", err)
	}

	ts := time.Now().Unix()
	popSig, err := signPoP(sshPub, priv, req.TargetUser, req.TargetIP, ts)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(Request{
		PublicKey:          string(ssh.MarshalAuthorizedKey(sshPub)),
		TargetUser:         req.TargetUser,
		TargetIP:           req.TargetIP,
		Timestamp:          ts,
		PopSignature:       popSig,
		SourceUser:         req.Client.SourceUser,
		ClientName:         req.Client.ClientName,
		ClientVersion:      req.Client.ClientVersion,
		AgentSignData:      base64.StdEncoding.EncodeToString(signData),
		HostKeyFingerprint: req.HostKeyFingerprint,
		SessionBinding: sessionBindingRequest{
			HostPublicKey: req.SessionBinding.HostPublicKey,
			SessionID:     req.SessionBinding.SessionID,
			Signature:     req.SessionBinding.Signature,
			Forwarding:    req.SessionBinding.Forwarding,
		},
		DestinationHostPublicKey: req.DestinationHostPublicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	txID, err := c.postSign(ctx, body)
	if err != nil {
		return nil, err
	}

	wait, err := c.getWait(ctx, txID)
	if err != nil {
		return nil, err
	}
	if wait.SSHSignature == "" {
		return nil, fmt.Errorf("empty ssh_signature in wait response")
	}
	blob, err := base64.StdEncoding.DecodeString(wait.SSHSignature)
	if err != nil {
		return nil, fmt.Errorf("decode ssh_signature: %w", err)
	}
	format := req.SignatureFormat
	if format == "" {
		format = sshPub.Type()
	}
	return &ssh.Signature{Format: format, Blob: blob}, nil
}
