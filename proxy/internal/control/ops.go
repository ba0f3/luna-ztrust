package control

import (
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/cli"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/mobile"
)

// ServerDeps are shared services for control operations.
type ServerDeps struct {
	Config      config.Config
	Keystore    *keystore.Keystore
	Mobile      *mobile.Store
	Pending     *keystore.PendingStore
	Cli         *cli.Store
	CSRSigner   *cli.CSRSigner
	LoadLimiter *cli.LoadRateLimiter
}

// Server handles control socket requests.
type Server struct {
	deps ServerDeps
}

// NewServer returns a control op dispatcher.
func NewServer(deps ServerDeps) *Server {
	if deps.Pending == nil {
		deps.Pending = keystore.NewPendingStore()
	}
	if deps.Cli == nil {
		deps.Cli = cli.NewStore()
	}
	return &Server{deps: deps}
}

func (s *Server) handle(req Request) Response {
	switch req.Op {
	case "status":
		return s.ok(req.ID, s.statusData())
	case "key.load":
		return s.handleKeyLoad(req)
	case "key.list":
		return s.ok(req.ID, s.keyListData())
	case "key.remove":
		return s.handleKeyRemove(req)
	case "key.confirm":
		return s.handleKeyConfirm(req)
	case "key.reject":
		return s.handleKeyReject(req)
	case "key.pending.list":
		return s.ok(req.ID, s.pendingListData())
	case "mobile.enroll":
		return s.handleMobileEnroll(req)
	case "mobile.list":
		return s.ok(req.ID, s.mobileListData())
	case "mobile.delete":
		return s.handleMobileDelete(req)
	case "cli.enroll":
		return s.handleCLIEnroll(req)
	case "cli.list":
		return s.ok(req.ID, s.cliListData())
	case "cli.delete":
		return s.handleCLIDelete(req)
	default:
		return s.fail(req.ID, "unknown op", "UNKNOWN")
	}
}

func (s *Server) statusData() json.RawMessage {
	data := map[string]any{
		"sealed":      !s.deps.Keystore.Available(),
		"signer_mode": s.deps.Config.SignerMode,
		"loaded":      s.deps.Keystore.ListSigners(),
		"pending":     s.deps.Pending.Count(),
	}
	b, _ := json.Marshal(data)
	return b
}

type keyLoadData struct {
	Path       string `json:"path"`
	Passphrase string `json:"passphrase"`
	Comment    string `json:"comment,omitempty"`
}

func (s *Server) handleKeyLoad(req Request) Response {
	var in keyLoadData
	if err := json.Unmarshal(req.Data, &in); err != nil {
		return s.fail(req.ID, "invalid json", "BAD_REQUEST")
	}
	if in.Path == "" || in.Passphrase == "" {
		return s.fail(req.ID, "path and passphrase required", "BAD_REQUEST")
	}
	pass := []byte(in.Passphrase)
	defer ZeroBytes(pass)
	fp, err := s.deps.Keystore.LoadPEMFile(in.Path, string(pass), in.Comment)
	if err != nil {
		if errors.Is(err, keystore.ErrUnsealLocked) {
			return s.fail(req.ID, err.Error(), "LOCKED")
		}
		return s.fail(req.ID, "load failed", "FORBIDDEN")
	}
	log.Printf("control: key_loaded fp=%s", fp)
	b, _ := json.Marshal(map[string]string{"fingerprint": fp})
	return s.ok(req.ID, b)
}

func (s *Server) keyListData() json.RawMessage {
	b, _ := json.Marshal(map[string]any{"signers": s.deps.Keystore.ListSigners()})
	return b
}

type keyRemoveData struct {
	Fingerprint string `json:"fingerprint"`
}

func (s *Server) handleKeyRemove(req Request) Response {
	var in keyRemoveData
	if err := json.Unmarshal(req.Data, &in); err != nil {
		return s.fail(req.ID, "invalid json", "BAD_REQUEST")
	}
	if err := s.deps.Keystore.RemoveSigner(in.Fingerprint); err != nil {
		return s.fail(req.ID, err.Error(), "NOT_FOUND")
	}
	log.Printf("control: key_removed fp=%s", in.Fingerprint)
	return s.ok(req.ID, nil)
}

type keyConfirmData struct {
	PendingID  string `json:"pending_id"`
	Passphrase string `json:"passphrase"`
}

func (s *Server) handleKeyConfirm(req Request) Response {
	if s.deps.Config.SignerMode != approval.SignerModeLocalKey {
		return s.fail(req.ID, "local-key mode required", "BAD_REQUEST")
	}
	var in keyConfirmData
	if err := json.Unmarshal(req.Data, &in); err != nil {
		return s.fail(req.ID, "invalid json", "BAD_REQUEST")
	}
	p, err := s.deps.Pending.Get(in.PendingID)
	if err != nil {
		return s.fail(req.ID, err.Error(), "NOT_FOUND")
	}
	pass := []byte(in.Passphrase)
	defer ZeroBytes(pass)
	fp, err := s.deps.Keystore.LoadPEMBytes(p.Blob, string(pass), p.Label)
	if err != nil {
		if errors.Is(err, keystore.ErrUnsealLocked) {
			return s.fail(req.ID, err.Error(), "LOCKED")
		}
		return s.fail(req.ID, "confirm failed", "FORBIDDEN")
	}
	_ = s.deps.Pending.Delete(in.PendingID)
	log.Printf("control: pending_confirmed fp=%s id=%s", fp, in.PendingID)
	b, _ := json.Marshal(map[string]string{"fingerprint": fp})
	return s.ok(req.ID, b)
}

type keyRejectData struct {
	PendingID string `json:"pending_id"`
}

func (s *Server) handleKeyReject(req Request) Response {
	var in keyRejectData
	if err := json.Unmarshal(req.Data, &in); err != nil {
		return s.fail(req.ID, "invalid json", "BAD_REQUEST")
	}
	if err := s.deps.Pending.Delete(in.PendingID); err != nil {
		return s.fail(req.ID, err.Error(), "NOT_FOUND")
	}
	return s.ok(req.ID, nil)
}

func (s *Server) pendingListData() json.RawMessage {
	list := s.deps.Pending.List()
	type item struct {
		ID        string `json:"id"`
		DeviceID  string `json:"device_id"`
		Label     string `json:"label"`
		Comment   string `json:"comment,omitempty"`
		ExpiresAt string `json:"expires_at"`
	}
	out := make([]item, 0, len(list))
	for _, p := range list {
		out = append(out, item{
			ID:        p.ID,
			DeviceID:  p.DeviceID,
			Label:     p.Label,
			Comment:   p.Comment,
			ExpiresAt: p.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	b, _ := json.Marshal(map[string]any{"pending": out})
	return b
}

type mobileEnrollData struct {
	Label           string `json:"label"`
	DevicePubKey    string `json:"device_pubkey"`
	CertFingerprint string `json:"cert_fingerprint"`
}

func (s *Server) handleMobileEnroll(req Request) Response {
	var in mobileEnrollData
	if err := json.Unmarshal(req.Data, &in); err != nil {
		return s.fail(req.ID, "invalid json", "BAD_REQUEST")
	}
	if in.CertFingerprint == "" {
		return s.fail(req.ID, "cert_fingerprint required", "BAD_REQUEST")
	}
	dev, err := s.deps.Mobile.EnrollBound(in.Label, in.DevicePubKey, in.CertFingerprint)
	if err != nil {
		return s.fail(req.ID, err.Error(), "BAD_REQUEST")
	}
	log.Printf("control: mobile_enroll device_id=%s", dev.ID)
	b, _ := json.Marshal(map[string]string{"device_id": dev.ID})
	return s.ok(req.ID, b)
}

func (s *Server) mobileListData() json.RawMessage {
	b, _ := json.Marshal(map[string]any{"devices": s.deps.Mobile.List()})
	return b
}

type mobileDeleteData struct {
	DeviceID string `json:"device_id"`
}

func (s *Server) handleMobileDelete(req Request) Response {
	var in mobileDeleteData
	if err := json.Unmarshal(req.Data, &in); err != nil {
		return s.fail(req.ID, "invalid json", "BAD_REQUEST")
	}
	if err := s.deps.Mobile.Delete(in.DeviceID); err != nil {
		return s.fail(req.ID, err.Error(), "NOT_FOUND")
	}
	return s.ok(req.ID, nil)
}

type cliEnrollData struct {
	Label  string `json:"label"`
	CSRPEM string `json:"csr_pem"`
}

func (s *Server) handleCLIEnroll(req Request) Response {
	if s.deps.CSRSigner == nil {
		return s.fail(req.ID, "CLI CSR signing not configured", "UNAVAILABLE")
	}
	var in cliEnrollData
	if err := json.Unmarshal(req.Data, &in); err != nil {
		return s.fail(req.ID, "invalid json", "BAD_REQUEST")
	}
	if in.Label == "" || in.CSRPEM == "" {
		return s.fail(req.ID, "label and csr_pem required", "BAD_REQUEST")
	}
	if err := cli.ValidateLabel(in.Label); err != nil {
		if errors.Is(err, cli.ErrEmptyLabel) || errors.Is(err, cli.ErrLabelTooLong) {
			return s.fail(req.ID, err.Error(), "BAD_REQUEST")
		}
		return s.fail(req.ID, "invalid label", "BAD_REQUEST")
	}

	certPEM, fp, err := s.deps.CSRSigner.Sign([]byte(in.CSRPEM))
	if err != nil {
		if errors.Is(err, cli.ErrCSRInvalid) {
			return s.fail(req.ID, err.Error(), "BAD_REQUEST")
		}
		return s.fail(req.ID, "sign failed", "FORBIDDEN")
	}

	dev, err := s.deps.Cli.Enroll(in.Label, fp)
	if err != nil {
		if errors.Is(err, cli.ErrEmptyLabel) || errors.Is(err, cli.ErrLabelTooLong) {
			return s.fail(req.ID, err.Error(), "BAD_REQUEST")
		}
		if errors.Is(err, cli.ErrDuplicateFingerprint) {
			return s.fail(req.ID, err.Error(), "CONFLICT")
		}
		return s.fail(req.ID, "enroll failed", "FORBIDDEN")
	}

	log.Printf("control: cli_enroll device_id=%s", dev.ID)
	b, _ := json.Marshal(map[string]string{
		"device_id":       dev.ID,
		"certificate_pem": string(certPEM),
	})
	return s.ok(req.ID, b)
}

func (s *Server) cliListData() json.RawMessage {
	devices := s.deps.Cli.List()
	type deviceJSON struct {
		DeviceID        string `json:"device_id"`
		Label           string `json:"label"`
		CertFingerprint string `json:"cert_fingerprint"`
		EnrolledAt      string `json:"enrolled_at"`
	}
	out := make([]deviceJSON, 0, len(devices))
	for _, d := range devices {
		out = append(out, deviceJSON{
			DeviceID:        d.ID,
			Label:           d.Label,
			CertFingerprint: d.CertFingerprint,
			EnrolledAt:      d.EnrolledAt.UTC().Format(time.RFC3339),
		})
	}
	b, _ := json.Marshal(map[string]any{"devices": out})
	return b
}

type cliDeleteData struct {
	DeviceID string `json:"device_id"`
}

func (s *Server) handleCLIDelete(req Request) Response {
	var in cliDeleteData
	if err := json.Unmarshal(req.Data, &in); err != nil {
		return s.fail(req.ID, "invalid json", "BAD_REQUEST")
	}
	if err := s.deps.Cli.Delete(in.DeviceID); err != nil {
		return s.fail(req.ID, err.Error(), "NOT_FOUND")
	}
	if s.deps.LoadLimiter != nil {
		s.deps.LoadLimiter.Forget(in.DeviceID)
	}
	log.Printf("control: cli_delete device_id=%s", in.DeviceID)
	return s.ok(req.ID, nil)
}

func (s *Server) ok(id string, data json.RawMessage) Response {
	return Response{OK: true, ID: id, Data: data}
}

func (s *Server) fail(id, msg, code string) Response {
	return Response{OK: false, ID: id, Error: msg, Code: code}
}
