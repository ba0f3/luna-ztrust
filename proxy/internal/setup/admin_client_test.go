package setup

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateAdminClient(t *testing.T) {
	pkiDir := t.TempDir()
	if _, err := GenerateMTLS(MTLSOptions{
		Dir:                  pkiDir,
		IncludeSampleClients: false,
		ServerDNSNames:       []string{"test.local"},
	}); err != nil {
		t.Fatal(err)
	}

	// Remove admin-client to simulate older setup without admin pair.
	_ = os.Remove(filepath.Join(pkiDir, "admin-client.crt"))
	_ = os.Remove(filepath.Join(pkiDir, "admin-client.key"))

	res, err := GenerateAdminClient(AdminClientOptions{Dir: pkiDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 2 {
		t.Fatalf("files = %v", res.Files)
	}

	adminCert := loadCert(t, filepath.Join(pkiDir, "admin-client.crt"))
	if !subjectHasOU(adminCert.Subject, "luna-admin") {
		t.Fatalf("admin OU missing: %v", adminCert.Subject.OrganizationalUnit)
	}
	caCert := loadCert(t, filepath.Join(pkiDir, "ca.crt"))
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := adminCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("admin cert not signed by CA: %v", err)
	}
}
