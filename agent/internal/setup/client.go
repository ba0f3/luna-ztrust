package setup

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultClientValidityDays = 3650

// ErrExists is returned when output files exist and Force is false.
var ErrExists = errors.New("client material already exists (use --force to overwrite)")

// ClientOptions configures mTLS client material for luna-agent.
type ClientOptions struct {
	Dir          string
	Force        bool
	CommonName   string
	Organization string
	ValidityDays int
}

// ClientResult lists written client key (and CSR if generated) paths.
type ClientResult struct {
	KeyPath string
	CSRPath string
}

// GenerateClientKey creates client.key under dir (and optional CSR).
func GenerateClientKey(opts ClientOptions) (ClientResult, error) {
	opts = opts.withDefaults()
	keyPath := filepath.Join(opts.Dir, "client.key")
	csrPath := filepath.Join(opts.Dir, "client.csr.pem")
	if !opts.Force {
		if _, err := os.Stat(keyPath); err == nil {
			return ClientResult{}, fmt.Errorf("%w: client.key", ErrExists)
		}
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return ClientResult{}, fmt.Errorf("create dir: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ClientResult{}, fmt.Errorf("generate client key: %w", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	if err := writeFile(keyPath, keyPEM, 0o600); err != nil {
		return ClientResult{}, err
	}

	cn := opts.CommonName
	if cn == "" {
		cn = "Luna Automation Client"
	}
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{opts.Organization},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return ClientResult{}, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err := writeFile(csrPath, csrPEM, 0o644); err != nil {
		return ClientResult{}, err
	}

	return ClientResult{KeyPath: keyPath, CSRPath: csrPath}, nil
}

// SignClientCSR signs a CSR with the Luna mTLS CA and writes client.crt.
func SignClientCSR(dir string, validityDays int, force bool) (string, error) {
	dir = filepath.Clean(dir)
	if validityDays <= 0 {
		validityDays = defaultClientValidityDays
	}
	certPath := filepath.Join(dir, "client.crt")
	if !force {
		if _, err := os.Stat(certPath); err == nil {
			return "", fmt.Errorf("%w: client.crt", ErrExists)
		}
	}
	caCert, caKey, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		return "", err
	}
	csrPEM, err := os.ReadFile(filepath.Join(dir, "client.csr.pem"))
	if err != nil {
		return "", fmt.Errorf("read client.csr.pem: %w", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", fmt.Errorf("parse client.csr.pem: no CSR block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return "", fmt.Errorf("sign client certificate: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeFile(certPath, pemBytes, 0o644); err != nil {
		return "", err
	}
	return certPath, nil
}

// InstallFile copies src to dst unless dst exists and force is false.
func InstallFile(src, dst string, mode os.FileMode, force bool) error {
	if src == "" {
		return nil
	}
	if !force {
		if _, err := os.Stat(dst); err == nil {
			return nil
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	return writeFile(dst, data, mode)
}

// InstallFromDir copies ca.crt, client.crt, client.key from srcDir when present.
func InstallFromDir(srcDir, dstDir string, force bool) error {
	srcDir = filepath.Clean(srcDir)
	pairs := []struct {
		name string
		mode os.FileMode
	}{
		{"ca.crt", 0o644},
		{"client.crt", 0o644},
		{"client.key", 0o600},
	}
	for _, p := range pairs {
		src := filepath.Join(srcDir, p.name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := InstallFile(src, filepath.Join(dstDir, p.name), p.mode, force); err != nil {
			return err
		}
	}
	return nil
}

func (o ClientOptions) withDefaults() ClientOptions {
	if strings.TrimSpace(o.Dir) == "" {
		o.Dir = DefaultCertsDir
	}
	o.Dir = filepath.Clean(o.Dir)
	if o.Organization == "" {
		o.Organization = "Luna Z-Trust"
	}
	return o
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
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
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("parse CA key: no PEM block")
	}
	var caKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse CA key: %w", err)
		}
	default:
		k, parseErr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("parse CA key: %w", parseErr)
		}
		var ok bool
		caKey, ok = k.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("CA key is not RSA")
		}
	}
	return caCert, caKey, nil
}

func clientMaterialReady(dir string) bool {
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}
	return true
}
