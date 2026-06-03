package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
	"github.com/ba0f3/luna-ztrust/proxy/internal/mobile"
)

type mobileEnrollRequest struct {
	Label        string `json:"label"`
	DevicePubKey string `json:"device_pubkey"`
}

type mobileEnrollResponse struct {
	DeviceID string `json:"device_id"`
}

type mobileApproveSignPayload struct {
	TxID       string `json:"tx_id"`
	Action     string `json:"action"`
	TTLSeconds int    `json:"ttl_seconds"`
	DeviceID   string `json:"device_id"`
	Timestamp  int64  `json:"timestamp"`
}

type mobileApproveRequest struct {
	mobileApproveSignPayload
	Signature string `json:"signature"`
}

const maxMobileBody = 64 << 10

func (s *server) handleMobileEnroll(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxMobileBody)
	var req mobileEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	dev, err := s.mobile.Enroll(req.Label, req.DevicePubKey)
	if err != nil {
		if errors.Is(err, mobile.ErrEmptyLabel) || errors.Is(err, mobile.ErrInvalidKey) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "enroll failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mobileEnrollResponse{DeviceID: dev.ID})
}

func (s *server) handleMobileDeleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("device_id")
	if id == "" {
		http.Error(w, "device_id required", http.StatusBadRequest)
		return
	}
	if err := s.mobile.Delete(id); err != nil {
		if errors.Is(err, mobile.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleMobileApprove(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxMobileBody)
	var req mobileApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Action != "approve" {
		http.Error(w, "unsupported action", http.StatusBadRequest)
		return
	}
	if req.TxID == "" || req.DeviceID == "" || req.Signature == "" {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}
	dev, ok := s.mobile.Get(req.DeviceID)
	if !ok {
		http.Error(w, "unknown device", http.StatusForbidden)
		return
	}

	payload := mobileApproveSignPayload{
		TxID:       req.TxID,
		Action:     req.Action,
		TTLSeconds: req.TTLSeconds,
		DeviceID:   req.DeviceID,
		Timestamp:  req.Timestamp,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "payload encode", http.StatusInternalServerError)
		return
	}
	if err := verifyDeviceSignature(dev.PubKey, payloadBytes, req.Signature, time.Now(), req.Timestamp); err != nil {
		writeDeviceAuthError(w, err)
		return
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = approval.DefaultTTLFromAllowed(s.cfg.AllowedTTLSeconds)
	} else if !approval.TTLAllowed(req.TTLSeconds, s.cfg.AllowedTTLSeconds) {
		http.Error(w, "ttl not allowed", http.StatusBadRequest)
		return
	}

	s.store.Approve(req.TxID, ttl, lease.FormatApproverDeviceID(req.DeviceID))
	w.WriteHeader(http.StatusOK)
}
