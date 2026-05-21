package sdk

import (
	"crypto/ed25519"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// NewCertSigner returns an ssh.Signer that presents cert as the public identity.
func NewCertSigner(cert *ssh.Certificate, priv ed25519.PrivateKey) (ssh.Signer, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("signer from private key: %w", err)
	}
	return ssh.NewCertSigner(cert, signer)
}
