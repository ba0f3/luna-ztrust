package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type cliKeysLoadWire struct {
	EncryptedPEM string          `json:"encrypted_pem"`
	Passphrase   json.RawMessage `json:"passphrase"`
	Label        string          `json:"label"`
	Comment      string          `json:"comment,omitempty"`
	Timestamp    int64           `json:"timestamp"`
}

type parsedCLIKeysLoad struct {
	EncryptedPEM string
	Passphrase   []byte
	Label        string
	Comment      string
	Timestamp    int64
}

func parseCLIKeysLoadBody(raw []byte) (parsedCLIKeysLoad, error) {
	var wire cliKeysLoadWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return parsedCLIKeysLoad{}, err
	}
	pass, err := decodeJSONStringField(wire.Passphrase)
	if err != nil {
		return parsedCLIKeysLoad{}, fmt.Errorf("passphrase: %w", err)
	}
	return parsedCLIKeysLoad{
		EncryptedPEM: wire.EncryptedPEM,
		Passphrase:   pass,
		Label:        wire.Label,
		Comment:      wire.Comment,
		Timestamp:    wire.Timestamp,
	}, nil
}

func decodeJSONStringField(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("required")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func writeCLIKeysLoadError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": msg,
		"code":  code,
	})
}
