package signing

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"golang.org/x/crypto/ssh"
)

// LocalCA signs SSH user certificates with a CA key held in the keystore.
type LocalCA struct {
	ks *keystore.Keystore
}

// NewLocalCA returns a CertIssuer backed by the unsealed keystore CA key.
func NewLocalCA(ks *keystore.Keystore) *LocalCA {
	return &LocalCA{ks: ks}
}

// IssueCert signs a user certificate for the client public key.
func (c *LocalCA) IssueCert(_ context.Context, req IssueRequest) (IssueResult, error) {
	caSigner, err := c.ks.SSHSigner()
	if err != nil {
		return IssueResult{}, err
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.ClientPubKey))
	if err != nil {
		return IssueResult{}, fmt.Errorf("parse client public key: %w", err)
	}

	now := time.Now()
	validAfter := uint64(now.Add(-30 * time.Second).Unix())
	validBefore := uint64(req.ValidUntil.Unix())
	if validBefore <= validAfter {
		return IssueResult{}, fmt.Errorf("invalid cert validity window")
	}

	perms := ssh.Permissions{}
	if req.SourceIP != "" {
		perms.CriticalOptions = map[string]string{"source-address": req.SourceIP}
	}
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          uint64(now.UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           req.TargetUser,
		ValidPrincipals: []string{req.TargetUser},
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
		Permissions:     perms,
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return IssueResult{}, fmt.Errorf("sign certificate: %w", err)
	}

	return IssueResult{
		Certificate: string(ssh.MarshalAuthorizedKey(cert)),
		ExpiresAt:   req.ValidUntil,
	}, nil
}
