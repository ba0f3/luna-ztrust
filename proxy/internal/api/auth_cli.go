package api

import (
	"crypto/x509"

	"github.com/ba0f3/luna-ztrust/proxy/internal/cli"
)

func cliClientAllowed(requiredOU string, cert *x509.Certificate) bool {
	if requiredOU == "" {
		return false
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		if ou == requiredOU {
			return true
		}
	}
	return false
}

func (s *server) cliDeviceFromPeer(cert *x509.Certificate) (*cli.Device, bool) {
	if s.cli == nil || cert == nil {
		return nil, false
	}
	return s.cli.GetByFingerprint(cli.CertFingerprint(cert))
}
