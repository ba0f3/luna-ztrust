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
	mode := s.cfg.SignerMode
	if mode == "" {
		mode = "local-ca"
	}
	allowed := s.cfg.AllowedTTLSeconds
	if len(allowed) == 0 {
		allowed = []int{180, 300, 900}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(capabilitiesResponse{
		SignerMode:        mode,
		LeaseSupported:    true,
		AllowedTTLSeconds: allowed,
		Sealed:            !s.keystore.Available(),
	})
}
