package setup

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

const defaultValidityDays = 3650

// ErrExists is returned when output files already exist and Force is false.
var ErrExists = errors.New("mTLS material already exists (use --force to overwrite)")

// MTLSOptions configures first-time mTLS PKI generation.
type MTLSOptions struct {
	Dir                  string
	Force                bool
	CACommonName         string
	Organization         string
	ServerCommonName     string
	ServerDNSNames       []string
	AdminClientOU        string
	ValidityDays         int
	IncludeSampleClients bool
}

// MTLSResult lists written file paths (absolute).
type MTLSResult struct {
	Files []string
}

// GenerateMTLS creates a Luna mTLS CA, server certificate, and optional sample client certs.
func GenerateMTLS(opts MTLSOptions) (MTLSResult, error) {
	opts = opts.withDefaults()
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return MTLSResult{}, fmt.Errorf("create output dir: %w", err)
	}

	outputs := []struct {
		name string
		mode os.FileMode
	}{
		{"ca.crt", 0o644},
		{"ca.key", 0o400},
		{"server.crt", 0o644},
		{"server.key", 0o400},
	}
	if opts.IncludeSampleClients {
		outputs = append(outputs,
			struct{ name string; mode os.FileMode }{"client.crt", 0o644},
			struct{ name string; mode os.FileMode }{"client.key", 0o600},
			struct{ name string; mode os.FileMode }{"admin-client.crt", 0o644},
			struct{ name string; mode os.FileMode }{"admin-client.key", 0o600},
		)
	}
	if !opts.Force {
		for _, o := range outputs {
			if _, err := os.Stat(filepath.Join(opts.Dir, o.name)); err == nil {
				return MTLSResult{}, fmt.Errorf("%w: %s", ErrExists, o.name)
			}
		}
	}

	days := opts.ValidityDays
	notBefore := time.Now().UTC().Add(-time.Minute)
	notAfter := notBefore.Add(time.Duration(days) * 24 * time.Hour)

	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return MTLSResult{}, fmt.Errorf("generate CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: opts.CACommonName, Organization: []string{opts.Organization}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return MTLSResult{}, fmt.Errorf("sign CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return MTLSResult{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	var written []string
	w, err := writePair(opts.Dir, "ca", 0o644, 0o400, caDER, caKey)
	if err != nil {
		return MTLSResult{}, err
	}
	written = append(written, w...)

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return MTLSResult{}, fmt.Errorf("generate server key: %w", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject:      pkix.Name{CommonName: opts.ServerCommonName, Organization: []string{opts.Organization}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     opts.ServerDNSNames,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return MTLSResult{}, fmt.Errorf("sign server certificate: %w", err)
	}
	w, err = writePair(opts.Dir, "server", 0o644, 0o400, serverDER, serverKey)
	if err != nil {
		return MTLSResult{}, err
	}
	written = append(written, w...)

	if opts.IncludeSampleClients {
		clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return MTLSResult{}, fmt.Errorf("generate client key: %w", err)
		}
		clientTemplate := &x509.Certificate{
			SerialNumber: mustSerial(),
			Subject:      pkix.Name{CommonName: "Luna Automation Client", Organization: []string{opts.Organization}},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
		if err != nil {
			return MTLSResult{}, fmt.Errorf("sign client certificate: %w", err)
		}
		w, err = writePair(opts.Dir, "client", 0o644, 0o600, clientDER, clientKey)
		if err != nil {
			return MTLSResult{}, err
		}
		written = append(written, w...)

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
		w, err = writePair(opts.Dir, "admin-client", 0o644, 0o600, adminDER, adminKey)
		if err != nil {
			return MTLSResult{}, err
		}
		written = append(written, w...)
	}

	return MTLSResult{Files: written}, nil
}

func (o MTLSOptions) withDefaults() MTLSOptions {
	if strings.TrimSpace(o.Dir) == "" {
		o.Dir = config.DefaultCertsDir
	}
	o.Dir = filepath.Clean(o.Dir)
	if o.CACommonName == "" {
		o.CACommonName = "Luna mTLS CA"
	}
	if o.Organization == "" {
		o.Organization = "Luna Z-Trust"
	}
	if o.ServerCommonName == "" {
		o.ServerCommonName = "luna-proxy"
	}
	if len(o.ServerDNSNames) == 0 {
		o.ServerDNSNames = []string{"localhost"}
	}
	if o.AdminClientOU == "" {
		o.AdminClientOU = "luna-admin"
	}
	if o.ValidityDays <= 0 {
		o.ValidityDays = defaultValidityDays
	}
	return o
}

func mustSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return serial
}

func writePair(dir, base string, certMode, keyMode os.FileMode, certDER []byte, key *rsa.PrivateKey) ([]string, error) {
	certPath := filepath.Join(dir, base+".crt")
	keyPath := filepath.Join(dir, base+".key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := writeFileAtomic(certPath, certPEM, certMode); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal %s key: %w", base, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeFileAtomic(keyPath, keyPEM, keyMode); err != nil {
		return nil, err
	}
	absCert, _ := filepath.Abs(certPath)
	absKey, _ := filepath.Abs(keyPath)
	return []string{absCert, absKey}, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
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

// ProxyYAMLHints returns optional proxy.yml overrides when not using production defaults.
func ProxyYAMLHints(dir string) string {
	dir = filepath.Clean(dir)
	if dir == config.DefaultCertsDir {
		return fmt.Sprintf(`# mTLS paths default to %s/ when unset (server.crt, server.key, ca.crt, ca.key).
# Override only if you used a non-default --dir:
# mtls_server_cert: %s/server.crt
`, config.DefaultCertsDir, dir)
	}
	return fmt.Sprintf(`# Optional proxy.yml overrides (defaults use %s when --dir matches):
mtls_server_cert: %s/server.crt
mtls_server_key: %s/server.key
mtls_client_ca: %s/ca.crt
mtls_ca_cert_path: %s/ca.crt
mtls_ca_key_path: %s/ca.key
`, config.DefaultCertsDir, dir, dir, dir, dir, dir)
}
