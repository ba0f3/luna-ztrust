package api

import (
	"crypto/x509"
	"net/http"
)

func (s *server) handleUnseal(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "admin unseal moved to luna-proxy key load via control socket", http.StatusGone)
}

func (s *server) handleSealStatus(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "admin seal-status moved to luna-proxy status via control socket", http.StatusGone)
}

func (s *server) withAdminMTLS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		if !adminClientAllowed(s.cfg.AdminClientOU, r.TLS.PeerCertificates[0]) {
			http.Error(w, "admin client certificate required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func adminClientAllowed(requiredOU string, cert *x509.Certificate) bool {
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
