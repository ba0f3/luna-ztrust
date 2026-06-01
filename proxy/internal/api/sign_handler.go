package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
)

const (
	maxSignRequestBody  = 64 << 10 // 64 KiB JSON body
	maxAgentSignDataB64 = 12 << 10 // base64 agent challenge cap
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

func signClientMeta(req auth.SignRequest) approval.ClientMeta {
	m := auth.NormalizeSignClientMeta(req.SourceUser, req.ClientName, req.ClientVersion)
	return approval.ClientMeta{
		SourceUser:    m.SourceUser,
		ClientName:    m.ClientName,
		ClientVersion: m.ClientVersion,
	}
}

func (s *server) handleSign(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	emptyMeta := auth.SignClientMeta{}
	r.Body = http.MaxBytesReader(w, r.Body, maxSignRequestBody)
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.logSignRequest(r, start, "", "", "", "body_too_large", emptyMeta)
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		s.logSignRequest(r, start, "", "", "", "read_body_error", emptyMeta)
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var req auth.SignRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		s.logSignRequest(r, start, "", "", "", "invalid_json", emptyMeta)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.BodyMAC = r.Header.Get("X-Luna-Body-Mac")
	clientMeta := auth.NormalizeSignClientMeta(req.SourceUser, req.ClientName, req.ClientVersion)

	conn, ok := tlsConnFromContext(r.Context())
	if !ok {
		s.logSignRequest(r, start, "", req.TargetUser, req.TargetIP, "tls_required", clientMeta)
		http.Error(w, "tls connection required", http.StatusUnauthorized)
		return
	}

	if err := auth.ValidateSignRequest(conn, rawBody, &req, time.Now(), s.replay); err != nil {
		s.logSignRequest(r, start, "", req.TargetUser, req.TargetIP, signOutcomeFromAuthErr(err), clientMeta)
		writeAuthError(w, err)
		return
	}

	if !s.keystore.Available() {
		s.logSignRequest(r, start, "", req.TargetUser, req.TargetIP, "sealed", clientMeta)
		http.Error(w, "sealed", http.StatusServiceUnavailable)
		return
	}

	clientFP := clientCertFPFromRequest(r)
	sourceIP := clientIPFromRemoteAddr(r.RemoteAddr)

	if s.cfg.SignerMode == approval.SignerModeLocalKey && req.AgentSignData == "" {
		s.logSignRequest(r, start, "", req.TargetUser, req.TargetIP, "missing_agent_sign_data", clientMeta)
		http.Error(w, "agent_sign_data required", http.StatusBadRequest)
		return
	}
	if len(req.AgentSignData) > maxAgentSignDataB64 {
		s.logSignRequest(r, start, "", req.TargetUser, req.TargetIP, "agent_sign_data_too_large", clientMeta)
		http.Error(w, "agent_sign_data too large", http.StatusRequestEntityTooLarge)
		return
	}

	hostKeyFP, err := s.resolveHostKeyFingerprint(&req)
	if err != nil {
		s.logSignRequest(r, start, "", req.TargetUser, req.TargetIP, "invalid_host_key", clientMeta)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	lookup := lease.NewLookupKey(clientFP, req.TargetUser, req.TargetIP, sourceIP, hostKeyFP)
	txMeta := signClientMeta(req)

	if s.cfg.Env != "dev" {
		if res, ok := s.store.IssueFromLease(r.Context(), lookup, req.PublicKey, req.AgentSignData, hostKeyFP); ok {
			tx := s.store.CreateInstantApproved(req.TargetUser, req.TargetIP, req.PublicKey, sourceIP, clientFP, res)
			s.logSignRequest(r, start, tx.ID, req.TargetUser, req.TargetIP, "lease_hit", clientMeta)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(signResponse{TxID: tx.ID})
			return
		}
	}

	tx, _ := s.store.Create(req.TargetUser, req.TargetIP, req.PublicKey, sourceIP, clientFP, req.AgentSignData, hostKeyFP, txMeta)
	if s.cfg.Env != "dev" {
		if s.telegram != nil && s.telegram.Configured() {
			go func() {
				if err := s.telegram.Notify(context.Background(), tx); err != nil {
					s.logTelegramEvent("notify", tx.ID, "failed", err.Error())
				} else {
					s.logTelegramEvent("notify", tx.ID, "sent", "")
				}
			}()
		} else {
			s.logTelegramEvent("notify", tx.ID, "skipped_unconfigured", "telegram_bot_token or telegram_chat_id missing")
		}
		go func() {
			_ = s.push.NotifyPending(context.Background(), tx)
		}()
	}
	s.logSignRequest(r, start, tx.ID, req.TargetUser, req.TargetIP, "accepted", clientMeta)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(signResponse{TxID: tx.ID})
}

func (s *server) handleWait(w http.ResponseWriter, r *http.Request) {
	txID := r.PathValue("tx_id")
	if bound, ok := s.store.ClientCertFP(txID); ok && bound != "" {
		if clientCertFPFromRequest(r) != bound {
			http.Error(w, approval.ErrWaitClientMismatch.Error(), http.StatusForbidden)
			return
		}
	}
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

func (s *server) resolveHostKeyFingerprint(req *auth.SignRequest) (string, error) {
	if s.cfg.SignerMode != approval.SignerModeLocalKey {
		return "", nil
	}
	fp, err := keystore.ResolveHostKeyFingerprint(req.HostPublicKey, req.HostKeyFingerprint)
	if err == nil {
		return fp, nil
	}
	if errors.Is(err, keystore.ErrAmbiguousSigner) {
		return s.keystore.SoleFingerprint()
	}
	return "", err
}

func writeWaitError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, approval.ErrWaitClientMismatch):
		http.Error(w, err.Error(), http.StatusForbidden)
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
