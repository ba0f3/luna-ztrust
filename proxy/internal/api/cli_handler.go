package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/cli"
	"github.com/ba0f3/luna-ztrust/proxy/internal/control"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
)

type cliEnrollRequest struct {
	Label  string `json:"label"`
	CSRPEM string `json:"csr_pem"`
}

type cliEnrollResponse struct {
	DeviceID       string `json:"device_id"`
	CertificatePEM string `json:"certificate_pem"`
}

type cliDeviceJSON struct {
	DeviceID        string `json:"device_id"`
	Label           string `json:"label"`
	CertFingerprint string `json:"cert_fingerprint"`
	EnrolledAt      string `json:"enrolled_at"`
}

type cliListDevicesResponse struct {
	Devices []cliDeviceJSON `json:"devices"`
}

type cliKeysLoadRequest struct {
	EncryptedPEM string `json:"encrypted_pem"`
	Passphrase   string `json:"passphrase"`
	Label        string `json:"label"`
	Comment      string `json:"comment,omitempty"`
}

type cliKeysLoadResponse struct {
	Fingerprint string `json:"fingerprint"`
}

const maxCLIKeyLoadBody = 64 << 10

func (s *server) handleCLIEnroll(w http.ResponseWriter, r *http.Request) {
	if s.csrSigner == nil {
		http.Error(w, "CLI CSR signing not configured", http.StatusServiceUnavailable)
		return
	}
	var req cliEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Label == "" || req.CSRPEM == "" {
		http.Error(w, "label and csr_pem required", http.StatusBadRequest)
		return
	}

	certPEM, fp, err := s.csrSigner.Sign([]byte(req.CSRPEM))
	if err != nil {
		if errors.Is(err, cli.ErrCSRInvalid) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, cli.ErrCANotConfigured) {
			http.Error(w, "CLI CSR signing not configured", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}

	dev, err := s.cli.Enroll(req.Label, fp)
	if err != nil {
		if errors.Is(err, cli.ErrEmptyLabel) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "enroll failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(cliEnrollResponse{
		DeviceID:       dev.ID,
		CertificatePEM: string(certPEM),
	})
}

func (s *server) handleCLIListDevices(w http.ResponseWriter, r *http.Request) {
	devices := s.cli.List()
	out := make([]cliDeviceJSON, 0, len(devices))
	for _, d := range devices {
		out = append(out, cliDeviceJSON{
			DeviceID:        d.ID,
			Label:           d.Label,
			CertFingerprint: d.CertFingerprint,
			EnrolledAt:      d.EnrolledAt.UTC().Format(time.RFC3339),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cliListDevicesResponse{Devices: out})
}

func (s *server) handleCLIDeleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("device_id")
	if id == "" {
		http.Error(w, "device_id required", http.StatusBadRequest)
		return
	}
	if err := s.cli.Delete(id); err != nil {
		if errors.Is(err, cli.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleCLIKeysLoad(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	peer := r.TLS.PeerCertificates[0]
	if adminClientAllowed(s.cfg.AdminClientOU, peer) {
		http.Error(w, "automation/admin cert cannot upload keys", http.StatusForbidden)
		return
	}
	if !cliClientAllowed(s.cfg.CliClientOU, peer) {
		http.Error(w, "cli client certificate required", http.StatusForbidden)
		return
	}
	dev, ok := s.cliDeviceFromPeer(peer)
	if !ok {
		http.Error(w, "unknown cli device", http.StatusForbidden)
		return
	}
	if s.cfg.SignerMode != approval.SignerModeLocalKey {
		http.Error(w, "local-key mode required", http.StatusBadRequest)
		return
	}
	if s.loadLimiter != nil && !s.loadLimiter.Allow(dev.ID) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxCLIKeyLoadBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req cliKeysLoadRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.EncryptedPEM == "" || req.Passphrase == "" || req.Label == "" {
		http.Error(w, "encrypted_pem, passphrase, and label required", http.StatusBadRequest)
		return
	}

	blob, err := base64.StdEncoding.DecodeString(req.EncryptedPEM)
	if err != nil {
		http.Error(w, "invalid encrypted_pem", http.StatusBadRequest)
		return
	}

	pass := []byte(req.Passphrase)
	defer control.ZeroBytes(pass)

	fp, err := s.keystore.LoadPEMBytes(blob, string(pass), req.Label)
	if err != nil {
		if errors.Is(err, keystore.ErrUnsealLocked) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
				"code":  "LOCKED",
			})
			return
		}
		http.Error(w, "load failed", http.StatusForbidden)
		return
	}

	if s.loadLimiter != nil {
		s.loadLimiter.RecordSuccess(dev.ID)
	}
	log.Printf("control: cli_key_loaded fp=%s device_id=%s", fp, dev.ID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cliKeysLoadResponse{Fingerprint: fp})
}
