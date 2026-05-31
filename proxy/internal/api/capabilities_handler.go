package api

import (
	"encoding/json"
	"net/http"
	"time"
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
	PublicKey   string `json:"public_key,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

func (s *server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sealed := !s.keystore.Available()
	var loaded []loadedSignerEntry
	if !sealed {
		for _, info := range s.keystore.ListSigners() {
			loaded = append(loaded, loadedSignerEntry{
				Fingerprint: info.Fingerprint,
				PublicKey:   info.PublicKey,
				Comment:     info.Comment,
			})
		}
	}
	s.logCapabilitiesRequest(r, start, sealed, len(loaded))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(capabilitiesResponse{
		SignerMode:        s.cfg.SignerMode,
		LeaseSupported:    true,
		AllowedTTLSeconds: s.cfg.AllowedTTLSeconds,
		Sealed:            sealed,
		LoadedSigners:     loaded,
	})
}
