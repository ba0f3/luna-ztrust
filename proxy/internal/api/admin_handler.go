package api

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
)

type unsealRequest struct {
	Passphrase string `json:"passphrase"`
}

type sealStatusResponse struct {
	Sealed bool `json:"sealed"`
}

func (s *server) handleUnseal(w http.ResponseWriter, r *http.Request) {
	var req unsealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Passphrase == "" {
		http.Error(w, "passphrase required", http.StatusBadRequest)
		return
	}
	if s.cfg.KeyPath == "" {
		http.Error(w, "key path not configured", http.StatusInternalServerError)
		return
	}
	if err := s.keystore.Unseal(s.cfg.KeyPath, req.Passphrase); err != nil {
		http.Error(w, "unseal failed", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleSealStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sealStatusResponse{Sealed: !s.keystore.Available()})
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
