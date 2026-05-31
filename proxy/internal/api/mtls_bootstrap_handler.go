package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/ba0f3/luna-ztrust/proxy/internal/cli"
)

const (
	maxMTLSEnrollBody = 64 << 10
	mtlsCAContentType = "application/x-pem-file"
)

type mtlsEnrollRequest struct {
	CSRPEM string `json:"csr_pem"`
}

type mtlsEnrollResponse struct {
	CertificatePEM string `json:"certificate_pem"`
}

func (s *server) handleMTLSCA(w http.ResponseWriter, _ *http.Request) {
	path := strings.TrimSpace(s.cfg.MTLSClientCA)
	if path == "" {
		path = strings.TrimSpace(s.cfg.MTLSCACertPath)
	}
	if path == "" {
		http.Error(w, "mTLS CA not configured", http.StatusServiceUnavailable)
		return
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "mTLS CA unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", mtlsCAContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pemBytes)
}

func (s *server) handleMTLSEnroll(w http.ResponseWriter, r *http.Request) {
	if s.csrSigner == nil {
		http.Error(w, "mTLS enrollment not configured", http.StatusServiceUnavailable)
		return
	}
	expected := strings.TrimSpace(s.cfg.MTLSEnrollToken)
	if expected == "" {
		http.Error(w, "mTLS enrollment disabled (set mtls_enroll_token)", http.StatusForbidden)
		return
	}
	got := strings.TrimSpace(r.Header.Get("X-Luna-Enroll-Token"))
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		http.Error(w, "invalid enroll token", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxMTLSEnrollBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	var req mtlsEnrollRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.CSRPEM) == "" {
		http.Error(w, "csr_pem required", http.StatusBadRequest)
		return
	}

	certPEM, _, err := s.csrSigner.SignAutomation([]byte(req.CSRPEM))
	if err != nil {
		if errors.Is(err, cli.ErrCSRInvalid) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, cli.ErrCANotConfigured) {
			http.Error(w, "mTLS enrollment not configured", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(mtlsEnrollResponse{CertificatePEM: string(certPEM)})
}
