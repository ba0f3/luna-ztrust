package api

import (
	"encoding/json"
	"net/http"
)

type capabilitiesResponse struct {
	SignerMode        string              `json:"signer_mode"`
	LeaseSupported    bool                `json:"lease_supported"`
	AllowedTTLSeconds []int               `json:"allowed_ttl_seconds"`
	Sealed            bool                `json:"sealed"`
	LoadedSigners     []loadedSignerEntry `json:"loaded_signers,omitempty"`
}

type loadedSignerEntry struct {
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
}

func (s *server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	var loaded []loadedSignerEntry
	if s.keystore.Available() {
		for _, info := range s.keystore.ListSigners() {
			loaded = append(loaded, loadedSignerEntry{
				Fingerprint: info.Fingerprint,
				Comment:     info.Comment,
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(capabilitiesResponse{
		SignerMode:        s.cfg.SignerMode,
		LeaseSupported:    true,
		AllowedTTLSeconds: s.cfg.AllowedTTLSeconds,
		Sealed:            !s.keystore.Available(),
		LoadedSigners:     loaded,
	})
}
