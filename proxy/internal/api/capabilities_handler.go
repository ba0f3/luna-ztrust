package api

import (
	"encoding/json"
	"net/http"
)

type capabilitiesResponse struct {
	SignerMode        string `json:"signer_mode"`
	LeaseSupported    bool   `json:"lease_supported"`
	AllowedTTLSeconds []int  `json:"allowed_ttl_seconds"`
	Sealed            bool   `json:"sealed"`
}

func (s *server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(capabilitiesResponse{
		SignerMode:        s.cfg.SignerMode,
		LeaseSupported:    true,
		AllowedTTLSeconds: s.cfg.AllowedTTLSeconds,
		Sealed:            !s.keystore.Available(),
	})
}
