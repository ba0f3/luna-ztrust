package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
)

const exporterLabel = "luna-request-hmac"

// ComputeBodyHMAC derives a 32-byte TLS exporter key and returns HMAC-SHA256 over body.
func ComputeBodyHMAC(conn *tls.Conn, body []byte) ([]byte, error) {
	state := conn.ConnectionState()
	key, err := state.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return mac.Sum(nil), nil
}

// FormatMACHeader hex-encodes the MAC for the X-Luna-Body-Mac header value.
func FormatMACHeader(mac []byte) string {
	return hex.EncodeToString(mac)
}
