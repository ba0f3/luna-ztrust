package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
)

const exporterLabel = "luna-request-hmac"

// ErrInvalidHMAC is returned when X-Luna-Body-Mac does not match the request body.
var ErrInvalidHMAC = errors.New("invalid body HMAC")

// VerifyBodyHMAC checks the header against HMAC-SHA256 of body using the TLS exporter key.
func VerifyBodyHMAC(conn *tls.Conn, body []byte, headerHex string) error {
	expected, err := computeBodyHMAC(conn, body)
	if err != nil {
		return err
	}
	provided, err := hex.DecodeString(headerHex)
	if err != nil {
		return ErrInvalidHMAC
	}
	if len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
		return ErrInvalidHMAC
	}
	return nil
}

// ComputeBodyHMAC returns HMAC-SHA256 of body using the TLS exporter key.
func ComputeBodyHMAC(conn *tls.Conn, body []byte) ([]byte, error) {
	return computeBodyHMAC(conn, body)
}

func computeBodyHMAC(conn *tls.Conn, body []byte) ([]byte, error) {
	state := conn.ConnectionState()
	key, err := state.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return mac.Sum(nil), nil
}
