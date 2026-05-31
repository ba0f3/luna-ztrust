package api

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
)

// signLogOut receives one JSON object per line for sign request outcomes.
// Tests may replace this writer; production defaults to stderr.
var signLogOut io.Writer = os.Stderr

type signLogEntry struct {
	Route         string `json:"route,omitempty"`
	TxID          string `json:"tx_id,omitempty"`
	ClientCertFP  string `json:"client_cert_fp,omitempty"`
	SourceIP      string `json:"source_ip,omitempty"`
	TargetUser    string `json:"target_user,omitempty"`
	TargetIP      string `json:"target_ip,omitempty"`
	Outcome       string `json:"outcome"`
	Sealed        bool   `json:"sealed,omitempty"`
	LoadedSigners int    `json:"loaded_signers,omitempty"`
	SignerMode    string `json:"signer_mode,omitempty"`
	LatencyMS     int64  `json:"latency_ms"`
}

// SwapSignLogOut replaces the access log sink for tests.
func SwapSignLogOut(w io.Writer) func() {
	old := signLogOut
	signLogOut = w
	return func() { signLogOut = old }
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
		Route:        "ssh/sign",
		TxID:         txID,
		ClientCertFP: clientCertFPFromRequest(r),
		SourceIP:     clientIPFromRemoteAddr(r.RemoteAddr),
		TargetUser:   targetUser,
		TargetIP:     targetIP,
		Outcome:      outcome,
		LatencyMS:    time.Since(start).Milliseconds(),
	})
}

func (s *server) logCapabilitiesRequest(r *http.Request, start time.Time, sealed bool, loadedCount int) {
	outcome := "ok"
	if sealed {
		outcome = "sealed"
	}
	emitSignLog(signLogEntry{
		Route:         "capabilities",
		ClientCertFP:  clientCertFPFromRequest(r),
		SourceIP:      clientIPFromRemoteAddr(r.RemoteAddr),
		Outcome:       outcome,
		Sealed:        sealed,
		LoadedSigners: loadedCount,
		SignerMode:    s.cfg.SignerMode,
		LatencyMS:     time.Since(start).Milliseconds(),
	})
}

func (s *server) logTelegramEvent(route, txID, outcome, detail string) {
	emitSignLog(signLogEntry{
		Route:   route,
		TxID:    txID,
		Outcome: outcome,
	})
	if detail != "" {
		log.Printf("telegram %s tx_id=%s outcome=%s detail=%s", route, txID, outcome, detail)
		return
	}
	log.Printf("telegram %s tx_id=%s outcome=%s", route, txID, outcome)
}
