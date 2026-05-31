package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
	"github.com/ba0f3/luna-ztrust/proxy/internal/cli"
	"github.com/ba0f3/luna-ztrust/proxy/internal/control"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
)

type cliEnrollRequest struct {
	Label  string `json:"label"`
	CSRPEM string `json:"csr_pem"`
}

type cliEnrollResponse struct {
	DeviceID       string `json:"device_id"`
	CertificatePEM string `json:"certificate_pem"`
}

type cliDeviceJSON struct {
	DeviceID        string `json:"device_id"`
	Label           string `json:"label"`
	CertFingerprint string `json:"cert_fingerprint"`
	EnrolledAt      string `json:"enrolled_at"`
}

type cliListDevicesResponse struct {
	Devices []cliDeviceJSON `json:"devices"`
}

type cliKeysLoadResponse struct {
	Fingerprint string `json:"fingerprint"`
}

const (
	maxCLIEnrollBody  = 64 << 10
	maxCLIKeyLoadBody = 64 << 10
)

func (s *server) handleCLIEnroll(w http.ResponseWriter, r *http.Request) {
	if s.csrSigner == nil {
		http.Error(w, "CLI CSR signing not configured", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCLIEnrollBody)
	var req cliEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.CSRPEM == "" {
		http.Error(w, "csr_pem required", http.StatusBadRequest)
		return
	}
	if err := cli.ValidateLabel(req.Label); err != nil {
		if errors.Is(err, cli.ErrEmptyLabel) || errors.Is(err, cli.ErrLabelTooLong) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "invalid label", http.StatusBadRequest)
		return
	}

	certPEM, fp, err := s.csrSigner.Sign([]byte(req.CSRPEM))
	if err != nil {
		if errors.Is(err, cli.ErrCSRInvalid) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, cli.ErrCANotConfigured) {
			http.Error(w, "CLI CSR signing not configured", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}

	dev, err := s.cli.Enroll(req.Label, fp)
	if err != nil {
		if errors.Is(err, cli.ErrEmptyLabel) || errors.Is(err, cli.ErrLabelTooLong) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, cli.ErrDuplicateFingerprint) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, "enroll failed", http.StatusInternalServerError)
		return
	}

	log.Printf("api: cli_enroll device_id=%s label=%s client_cert_fp=%s", dev.ID, dev.Label, fp)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(cliEnrollResponse{
		DeviceID:       dev.ID,
		CertificatePEM: string(certPEM),
	})
}

func (s *server) handleCLIListDevices(w http.ResponseWriter, r *http.Request) {
	devices := s.cli.List()
	out := make([]cliDeviceJSON, 0, len(devices))
	for _, d := range devices {
		out = append(out, cliDeviceJSON{
			DeviceID:        d.ID,
			Label:           d.Label,
			CertFingerprint: d.CertFingerprint,
			EnrolledAt:      d.EnrolledAt.UTC().Format(time.RFC3339),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cliListDevicesResponse{Devices: out})
}

func (s *server) handleCLIDeleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("device_id")
	if id == "" {
		http.Error(w, "device_id required", http.StatusBadRequest)
		return
	}
	if err := s.cli.Delete(id); err != nil {
		if errors.Is(err, cli.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	if s.loadLimiter != nil {
		s.loadLimiter.Forget(id)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleCLIKeysLoad(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		denyCLIKeysLoad(w, http.StatusUnauthorized, "CLIENT_CERT_REQUIRED", "client certificate required", "")
		return
	}
	peer := r.TLS.PeerCertificates[0]
	if adminClientAllowed(s.cfg.AdminClientOU, peer) {
		denyCLIKeysLoad(w, http.StatusForbidden, "FORBIDDEN_ADMIN", "automation/admin cert cannot upload keys", "")
		return
	}
	if !cliClientAllowed(s.cfg.CliClientOU, peer) {
		denyCLIKeysLoad(w, http.StatusForbidden, "FORBIDDEN_CLI_CERT", "cli client certificate required", "")
		return
	}
	dev, ok := s.cliDeviceFromPeer(peer)
	if !ok {
		denyCLIKeysLoad(w, http.StatusForbidden, "UNKNOWN_DEVICE", "unknown cli device", "")
		return
	}
	if s.cfg.SignerMode != approval.SignerModeLocalKey {
		writeCLIKeysLoadError(w, http.StatusBadRequest, "SIGNER_MODE", "local-key mode required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxCLIKeyLoadBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeCLIKeysLoadError(w, http.StatusBadRequest, "READ_BODY", "read body")
		return
	}
	defer control.ZeroBytes(raw)

	conn, ok := tlsConnFromContext(r.Context())
	if !ok {
		denyCLIKeysLoad(w, http.StatusUnauthorized, "TLS_REQUIRED", "tls connection required", dev.ID)
		return
	}

	parsed, err := parseCLIKeysLoadBody(raw)
	if err != nil {
		writeCLIKeysLoadError(w, http.StatusBadRequest, "INVALID_JSON", "invalid json")
		return
	}
	defer control.ZeroBytes(parsed.Passphrase)

	if err := auth.ValidateCLIKeysLoad(conn, raw, r.Header.Get("X-Luna-Body-Mac"), parsed.Timestamp, time.Now(), s.replay); err != nil {
		writeCLIKeysLoadAuthError(w, dev.ID, err)
		return
	}

	if parsed.EncryptedPEM == "" || len(parsed.Passphrase) == 0 || parsed.Label == "" {
		writeCLIKeysLoadError(w, http.StatusBadRequest, "MISSING_FIELDS", "encrypted_pem, passphrase, and label required")
		return
	}
	if err := cli.ValidateLabel(parsed.Label); err != nil {
		writeCLIKeysLoadError(w, http.StatusBadRequest, "INVALID_LABEL", err.Error())
		return
	}

	if s.loadLimiter != nil && !s.loadLimiter.Allowed(dev.ID) {
		denyCLIKeysLoad(w, http.StatusTooManyRequests, "RATE_LIMIT", "rate limit exceeded", dev.ID)
		return
	}

	blob, err := base64.StdEncoding.DecodeString(parsed.EncryptedPEM)
	if err != nil {
		writeCLIKeysLoadError(w, http.StatusBadRequest, "INVALID_PEM", "invalid encrypted_pem")
		return
	}

	fp, err := s.keystore.LoadPEMBytes(blob, string(parsed.Passphrase), parsed.Label)
	if err != nil {
		if errors.Is(err, keystore.ErrUnsealLocked) {
			writeCLIKeysLoadError(w, http.StatusForbidden, "LOCKED", err.Error())
			return
		}
		writeCLIKeysLoadError(w, http.StatusForbidden, "LOAD_FAILED", "load failed")
		return
	}
	if s.loadLimiter != nil && !s.loadLimiter.TryRecordSuccess(dev.ID) {
		log.Printf("auth: cli_keys_load rate_limit accounting mismatch device_id=%s fp=%s", dev.ID, fp)
	}

	log.Printf("control: cli_key_loaded fp=%s device_id=%s", fp, dev.ID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cliKeysLoadResponse{Fingerprint: fp})
}

func writeCLIKeysLoadAuthError(w http.ResponseWriter, deviceID string, err error) {
	switch {
	case errors.Is(err, auth.ErrReplay):
		denyCLIKeysLoad(w, http.StatusConflict, "REPLAY", err.Error(), deviceID)
	case errors.Is(err, auth.ErrInvalidHMAC):
		denyCLIKeysLoad(w, http.StatusUnauthorized, "INVALID_HMAC", err.Error(), deviceID)
	case errors.Is(err, auth.ErrTimestampOutsideWindow):
		denyCLIKeysLoad(w, http.StatusUnauthorized, "TIMESTAMP", err.Error(), deviceID)
	default:
		denyCLIKeysLoad(w, http.StatusBadRequest, "AUTH", err.Error(), deviceID)
	}
}
