package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"github.com/ba0f3/luna-ztrust/sdk"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// capabilityClient fetches proxy capabilities for identity discovery.
type capabilityClient interface {
	SignerMode() string
	FetchCapabilities(ctx context.Context) (sdk.Capabilities, error)
}

// ResolveIdentities returns ssh-agent keys OpenSSH should offer for authentication.
func ResolveIdentities(client capabilityClient, cfg Config) ([]*agent.Key, error) {
	caps, err := client.FetchCapabilities(context.Background())
	if err != nil {
		return nil, fmt.Errorf("fetch capabilities: %w", err)
	}

	mode := caps.SignerMode
	if mode == "" {
		mode = client.SignerMode()
	}
	if mode == "" {
		mode = cfg.SignerMode
	}

	switch mode {
	case SignerModeLocalKey:
		return resolveLocalKeyIdentities(caps, cfg)
	default:
		return resolveLocalCAIdentities()
	}
}

func resolveLocalCAIdentities() ([]*agent.Key, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("ssh signer: %w", err)
	}
	return []*agent.Key{agentKeyFromPublic(signer.PublicKey())}, nil
}

func resolveLocalKeyIdentities(caps sdk.Capabilities, cfg Config) ([]*agent.Key, error) {
	if caps.Sealed {
		return nil, fmt.Errorf("proxy keystore is sealed; on the proxy host load a signing key: luna-proxy key load <encrypted-key>")
	}
	if len(caps.LoadedSigners) == 0 {
		return nil, fmt.Errorf("no host signing keys loaded on proxy (use: luna-proxy key load)")
	}

	fallbackLine, err := loadHostedPublicKeyLine(cfg.HostedPublicKey)
	if err != nil {
		return nil, err
	}
	fallbackPub, _ := parsePublicKeyLine(fallbackLine)

	filter := normalizeFingerprintHint(cfg.HostKeyFingerprint)
	var keys []*agent.Key
	missingPubKey := 0

	for _, s := range caps.LoadedSigners {
		if filter != "" && normalizeFingerprintHint(s.Fingerprint) != filter {
			continue
		}

		pubLine := strings.TrimSpace(s.PublicKey)
		if pubLine == "" && fallbackPub != nil {
			if filter != "" || len(caps.LoadedSigners) == 1 {
				if fp := PublicKeyFingerprint(fallbackPub); filter == "" || normalizeFingerprintHint(s.Fingerprint) == fp {
					pubLine = fallbackLine
				}
			}
		}
		if pubLine == "" {
			missingPubKey++
			continue
		}

		pub, err := parsePublicKeyLine(pubLine)
		if err != nil {
			return nil, fmt.Errorf("parse loaded signer public key: %w", err)
		}
		keys = append(keys, agentKeyFromPublic(pub))
	}

	if len(keys) == 0 && missingPubKey > 0 {
		return nil, fmt.Errorf(
			"proxy has %d loaded key(s) but capabilities returned no public_key; rebuild luna-proxy (make build) or set hosted_public_key in agent config",
			missingPubKey,
		)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no matching host signing keys (check host_key_fingerprint or hosted_public_key)")
	}
	return keys, nil
}

func loadHostedPublicKeyLine(pathOrLine string) (string, error) {
	pathOrLine = strings.TrimSpace(pathOrLine)
	if pathOrLine == "" {
		return "", nil
	}
	if strings.HasPrefix(pathOrLine, "ssh-") {
		return pathOrLine, nil
	}
	raw, err := os.ReadFile(pathOrLine)
	if err != nil {
		return "", fmt.Errorf("read hosted_public_key: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func parsePublicKeyLine(line string) (ssh.PublicKey, error) {
	if line == "" {
		return nil, fmt.Errorf("empty public key")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		pub, err = ssh.ParsePublicKey([]byte(line))
		if err != nil {
			return nil, err
		}
	}
	return pub, nil
}

func agentKeyFromPublic(pub ssh.PublicKey) *agent.Key {
	return &agent.Key{
		Format: pub.Type(),
		Blob:   pub.Marshal(),
	}
}
