package setup

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AdminClientOptions configures admin-client.crt/key issuance from an existing CA.
type AdminClientOptions struct {
	Dir           string
	Force         bool
	AdminClientOU string
	Organization  string
	ValidityDays  int
}

// GenerateAdminClient issues admin-client.crt/key signed by ca.crt+ca.key in Dir.
func GenerateAdminClient(opts AdminClientOptions) (MTLSResult, error) {
	opts = opts.withDefaults()
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return MTLSResult{}, fmt.Errorf("create output dir: %w", err)
	}

	outCert := filepath.Join(opts.Dir, "admin-client.crt")
	outKey := filepath.Join(opts.Dir, "admin-client.key")
	if !opts.Force {
		for _, p := range []string{outCert, outKey} {
			if _, err := os.Stat(p); err == nil {
				return MTLSResult{}, fmt.Errorf("%w: %s", ErrExists, filepath.Base(p))
			}
		}
	}

	caCert, caKey, err := loadCAKeyPair(filepath.Join(opts.Dir, "ca.crt"), filepath.Join(opts.Dir, "ca.key"))
	if err != nil {
		return MTLSResult{}, err
	}

	days := opts.ValidityDays
	notBefore := time.Now().UTC().Add(-time.Minute)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)

	adminKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return MTLSResult{}, fmt.Errorf("generate admin client key: %w", err)
	}
	adminTemplate := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject: pkix.Name{
			CommonName:         "Luna Admin Client",
			Organization:       []string{opts.Organization},
			OrganizationalUnit: []string{opts.AdminClientOU},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	adminDER, err := x509.CreateCertificate(rand.Reader, adminTemplate, caCert, &adminKey.PublicKey, caKey)
	if err != nil {
		return MTLSResult{}, fmt.Errorf("sign admin client certificate: %w", err)
	}
	written, err := writePair(opts.Dir, "admin-client", 0o644, 0o600, adminDER, adminKey)
	if err != nil {
		return MTLSResult{}, err
	}
	return MTLSResult{Files: written}, nil
}

func (o AdminClientOptions) withDefaults() AdminClientOptions {
	if o.Dir == "" {
		o.Dir = defaultCertsDirFromMTLS()
	}
	o.Dir = filepath.Clean(o.Dir)
	if o.AdminClientOU == "" {
		o.AdminClientOU = "luna-admin"
	}
	if o.Organization == "" {
		o.Organization = "Luna Z-Trust"
	}
	if o.ValidityDays <= 0 {
		o.ValidityDays = defaultValidityDays
	}
	return o
}

func defaultCertsDirFromMTLS() string {
	o := MTLSOptions{}.withDefaults()
	return o.Dir
}

func loadCAKeyPair(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("parse CA cert: no PEM block")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("parse CA key: no PEM block")
	}
	var caKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			err = parseErr
			break
		}
		var ok bool
		caKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("parse CA key: expected RSA private key")
		}
	default:
		return nil, nil, fmt.Errorf("parse CA key: unsupported PEM type %q", block.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	return caCert, caKey, nil
}
