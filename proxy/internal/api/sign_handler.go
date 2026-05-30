package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
)

type signResponse struct {
	TxID string `json:"tx_id"`
}

type waitResponse struct {
	SSHCertificate string `json:"ssh_certificate,omitempty"`
	SSHSignature   string `json:"ssh_signature,omitempty"`
	ExpiresAt      string `json:"expires_at"`
	LeaseExpiresAt string `json:"lease_expires_at,omitempty"`
}

func (s *server) handleSign(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		s.logSignRequest(r, start, "", "", "", "read_body_error")
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var req auth.SignRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		s.logSignRequest(r, start, "", "", "", "invalid_json")
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.BodyMAC = r.Header.Get("X-Luna-Body-Mac")

	conn, ok := tlsConnFromContext(r.Context())
	if !ok {
		s.logSignRequest(r, start, "", req.TargetUser, req.TargetIP, "tls_required")
		http.Error(w, "tls connection required", http.StatusUnauthorized)
		return
	}

	if err := auth.ValidateSignRequest(conn, rawBody, &req, time.Now(), s.replay); err != nil {
		s.logSignRequest(r, start, "", req.TargetUser, req.TargetIP, signOutcomeFromAuthErr(err))
		writeAuthError(w, err)
		return
	}

	if !s.keystore.Available() {
		s.logSignRequest(r, start, "", req.TargetUser, req.TargetIP, "sealed")
		http.Error(w, "sealed", http.StatusServiceUnavailable)
		return
	}

	clientFP := clientCertFPFromRequest(r)
	sourceIP := clientIPFromRemoteAddr(r.RemoteAddr)
	lookup := lease.NewLookupKey(clientFP, req.TargetUser, req.TargetIP, sourceIP)

	if s.cfg.SignerMode == approval.SignerModeLocalKey && req.AgentSignData == "" {
		s.logSignRequest(r, start, "", req.TargetUser, req.TargetIP, "missing_agent_sign_data")
		http.Error(w, "agent_sign_data required", http.StatusBadRequest)
		return
	}

	if s.cfg.Env != "dev" {
		if res, ok := s.store.IssueFromLease(r.Context(), lookup, req.PublicKey, req.AgentSignData); ok {
			tx := s.store.CreateInstantApproved(req.TargetUser, req.TargetIP, req.PublicKey, sourceIP, res)
			s.logSignRequest(r, start, tx.ID, req.TargetUser, req.TargetIP, "lease_hit")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(signResponse{TxID: tx.ID})
			return
		}
	}

	tx, _ := s.store.Create(req.TargetUser, req.TargetIP, req.PublicKey, sourceIP, clientFP, req.AgentSignData)
	if s.cfg.Env != "dev" {
		if s.telegram != nil {
			go func() {
				_ = s.telegram.Notify(r.Context(), tx)
			}()
		}
		go func() {
			_ = s.push.NotifyPending(r.Context(), tx)
		}()
	}
	s.logSignRequest(r, start, tx.ID, req.TargetUser, req.TargetIP, "accepted")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(signResponse{TxID: tx.ID})
}

func (s *server) handleWait(w http.ResponseWriter, r *http.Request) {
	txID := r.PathValue("tx_id")
	cert, signature, expiresAt, leaseExpiresAt, err := s.store.Wait(r.Context(), txID)
	if err != nil {
		writeWaitError(w, err)
		return
	}

	expStr := formatTimeRFC3339(expiresAt, 5*time.Minute)
	leaseStr := ""
	if !leaseExpiresAt.IsZero() {
		leaseStr = leaseExpiresAt.UTC().Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(waitResponse{
		SSHCertificate: cert,
		SSHSignature:   signature,
		ExpiresAt:      expStr,
		LeaseExpiresAt: leaseStr,
	})
}

func formatTimeRFC3339(t time.Time, fallbackTTL time.Duration) string {
	if t.IsZero() {
		return time.Now().Add(fallbackTTL).UTC().Format(time.RFC3339)
	}
	return t.UTC().Format(time.RFC3339)
}

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrReplay):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, auth.ErrInvalidHMAC),
		errors.Is(err, auth.ErrInvalidPoP),
		errors.Is(err, auth.ErrTimestampOutsideWindow):
		http.Error(w, err.Error(), http.StatusUnauthorized)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func writeWaitError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, approval.ErrDenied):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, approval.ErrTimeout):
		http.Error(w, err.Error(), http.StatusRequestTimeout)
	case errors.Is(err, approval.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
