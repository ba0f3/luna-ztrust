package api

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
)

// signLogOut receives one JSON object per line for sign request outcomes.
// Tests may replace this writer; production defaults to stderr.
var signLogOut io.Writer = os.Stderr

type signLogEntry struct {
	TxID         string `json:"tx_id,omitempty"`
	ClientCertFP string `json:"client_cert_fp,omitempty"`
	TargetUser   string `json:"target_user,omitempty"`
	TargetIP     string `json:"target_ip,omitempty"`
	Outcome      string `json:"outcome"`
	LatencyMS    int64  `json:"latency_ms"`
}

func emitSignLog(e signLogEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = signLogOut.Write(b)
}

func clientCertFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func clientCertFPFromRequest(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return clientCertFingerprint(r.TLS.PeerCertificates[0])
}

func signOutcomeFromAuthErr(err error) string {
	switch {
	case errors.Is(err, auth.ErrReplay):
		return "replay"
	case errors.Is(err, auth.ErrInvalidHMAC):
		return "invalid_hmac"
	case errors.Is(err, auth.ErrInvalidPoP):
		return "invalid_pop"
	case errors.Is(err, auth.ErrTimestampOutsideWindow):
		return "timestamp_outside_window"
	default:
		return "auth_rejected"
	}
}

func (s *server) logSignRequest(r *http.Request, start time.Time, txID, targetUser, targetIP, outcome string) {
	emitSignLog(signLogEntry{
		TxID:         txID,
		ClientCertFP: clientCertFPFromRequest(r),
		TargetUser:   targetUser,
		TargetIP:     targetIP,
		Outcome:      outcome,
		LatencyMS:    time.Since(start).Milliseconds(),
	})
}
