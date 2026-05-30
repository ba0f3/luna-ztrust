package api

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
)

const maxPendingKeyBody = 64 << 10

type mobileKeysPendingRequest struct {
	DeviceID     string `json:"device_id"`
	EncryptedPEM string `json:"encrypted_pem"`
	Label        string `json:"label"`
	Comment      string `json:"comment,omitempty"`
}

type mobileKeysPendingResponse struct {
	PendingID string `json:"pending_id"`
}

func (s *server) handleMobileKeysPending(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if adminClientAllowed(s.cfg.AdminClientOU, r.TLS.PeerCertificates[0]) {
			http.Error(w, "automation/admin cert cannot upload keys", http.StatusForbidden)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPendingKeyBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req mobileKeysPendingRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.DeviceID == "" || req.EncryptedPEM == "" || req.Label == "" {
		http.Error(w, "device_id, encrypted_pem, and label required", http.StatusBadRequest)
		return
	}
	if _, ok := s.mobile.Get(req.DeviceID); !ok {
		http.Error(w, "unknown device", http.StatusForbidden)
		return
	}
	blob, err := base64.StdEncoding.DecodeString(req.EncryptedPEM)
	if err != nil {
		http.Error(w, "invalid encrypted_pem", http.StatusBadRequest)
		return
	}
	id, err := s.pending.Add(req.DeviceID, req.Label, req.Comment, blob)
	if err != nil {
		if err == keystore.ErrPendingFull {
			http.Error(w, "pending queue full", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(mobileKeysPendingResponse{PendingID: id})
}
