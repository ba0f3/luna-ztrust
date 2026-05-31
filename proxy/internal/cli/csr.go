package cli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

var (
	ErrCSRInvalid      = errors.New("invalid certificate signing request")
	ErrCANotConfigured = errors.New("mTLS CA certificate and key paths required")
)

// defaultCLIClientCertTTL is the lifetime for issued CLI client certificates.
// Workstation identity certs are long-lived; re-enroll via admin if revoked.
const defaultCLIClientCertTTL = 365 * 24 * time.Hour

// CSRSigner validates enrollment CSRs and issues mTLS client certificates.
type CSRSigner struct {
	caCert     *x509.Certificate
	caKey      crypto.PrivateKey
	requiredOU string
	ttl        time.Duration
}

// NewCSRSigner returns a signer that issues client-auth certs from validated CSRs.
func NewCSRSigner(caCert *x509.Certificate, caKey crypto.PrivateKey, requiredOU string, ttl time.Duration) *CSRSigner {
	return &CSRSigner{
		caCert:     caCert,
		caKey:      caKey,
		requiredOU: requiredOU,
		ttl:        ttl,
	}
}

// NewCSRSignerFromConfig loads CA material from cfg and returns a signer.
// Returns (nil, nil) when both CA paths are unset; ErrCANotConfigured when only one is set.
func NewCSRSignerFromConfig(cfg config.Config) (*CSRSigner, error) {
	certPath := strings.TrimSpace(cfg.MTLSCACertPath)
	keyPath := strings.TrimSpace(cfg.MTLSCAKeyPath)
	if certPath == "" && keyPath == "" {
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, ErrCANotConfigured
	}

	caCert, caKey, err := loadCAFromFiles(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	requiredOU := strings.TrimSpace(cfg.CliClientOU)
	if requiredOU == "" {
		requiredOU = "luna-cli"
	}
	return NewCSRSigner(caCert, caKey, requiredOU, defaultCLIClientCertTTL), nil
}

// Sign validates csrPEM and returns a signed client certificate PEM and its fingerprint.
func (s *CSRSigner) Sign(csrPEM []byte) (certPEM []byte, fingerprint string, err error) {
	if s == nil || s.caCert == nil || s.caKey == nil {
		return nil, "", ErrCANotConfigured
	}

	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, "", err
	}
	if err := validateCSR(csr, s.requiredOU); err != nil {
		return nil, "", err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(s.ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, "", fmt.Errorf("sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", fmt.Errorf("parse issued certificate: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return pemBytes, CertFingerprint(cert), nil
}

func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, ErrCSRInvalid
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, ErrCSRInvalid
	}
	return csr, nil
}

func validateCSR(csr *x509.CertificateRequest, requiredOU string) error {
	if err := csr.CheckSignature(); err != nil {
		return ErrCSRInvalid
	}
	if !subjectHasOU(csr.Subject, requiredOU) {
		return ErrCSRInvalid
	}
	if err := validateCSRPublicKey(csr.PublicKey); err != nil {
		return err
	}
	return nil
}

func subjectHasOU(subject pkix.Name, requiredOU string) bool {
	for _, ou := range subject.OrganizationalUnit {
		if ou == requiredOU {
			return true
		}
	}
	return false
}

func validateCSRPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return ErrCSRInvalid
		}
	case *ecdsa.PublicKey:
		// ECDSA keys are accepted; curve strength is enforced by CreateCertificateRequest.
	default:
		return ErrCSRInvalid
	}
	return nil
}

func loadCAFromFiles(certPath, keyPath string) (*x509.Certificate, crypto.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read mTLS CA cert: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("parse mTLS CA cert: no certificate block")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse mTLS CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read mTLS CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("parse mTLS CA key: no PEM block")
	}

	var caKey crypto.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		caKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	default:
		return nil, nil, fmt.Errorf("parse mTLS CA key: unsupported PEM type %q", keyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse mTLS CA key: %w", err)
	}
	return caCert, caKey, nil
}
