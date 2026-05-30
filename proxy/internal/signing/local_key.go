package signing

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
)

// LocalKey signs SSH agent challenge bytes with a hosted private key.
type LocalKey struct {
	ks *keystore.Keystore
}

// NewLocalKey returns a signer backed by the unsealed keystore host key.
func NewLocalKey(ks *keystore.Keystore) *LocalKey {
	return &LocalKey{ks: ks}
}

// SignAgent signs data using the hosted SSH private key identified by hostFP.
func (k *LocalKey) SignAgent(_ context.Context, hostFP string, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty sign data")
	}
	if hostFP == "" {
		return nil, fmt.Errorf("host key fingerprint required")
	}
	signer, err := k.ks.SignerForFingerprint(hostFP)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, fmt.Errorf("sign agent data: %w", err)
	}
	return sig.Blob, nil
}
