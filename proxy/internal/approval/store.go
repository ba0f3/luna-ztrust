package approval

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
	"github.com/ba0f3/luna-ztrust/proxy/internal/signing"
	"github.com/oklog/ulid/v2"
)

// Signer mode constants match LUNA_SIGNER_MODE.
const (
	SignerModeLocalCA  = "local-ca"
	SignerModeLocalKey = "local-key"
)

// State is the approval transaction lifecycle state.
type State string

const (
	StatePending   State = "pending"
	StateApproving State = "approving"
	StateApproved  State = "approved"
	StateDenied    State = "denied"
	StateExpired   State = "expired"
)

// DefaultDevCertTTL is the credential lifetime used for LUNA_ENV=dev auto-approve.
const DefaultDevCertTTL = 5 * time.Minute

// Transaction is a pending or terminal SSH sign approval request.
type Transaction struct {
	ID                            string
	TargetUser                    string
	TargetIP                      string
	PublicKey                     string
	SourceIP                      string
	SourceUser                    string
	ClientName                    string
	ClientVersion                 string
	ClientCertFP                  string
	AgentSignData                 string
	HostKeyFingerprint            string
	DestinationHostKeyFingerprint string
	DestinationHostKeySource      string
	DisableLease                  bool
	State                         State
	CreatedAt                     time.Time
}

// ClientMeta is optional metadata from the sign request (display/audit only).
type ClientMeta struct {
	SourceUser               string
	ClientName               string
	ClientVersion            string
	DestinationHostKeySource string
	DisableLease             bool
}

// Result is delivered to waiters when a transaction reaches a terminal state.
type Result struct {
	Cert           string
	Signature      string
	ExpiresAt      time.Time
	LeaseExpiresAt time.Time
	Err            error
}

var (
	ErrNotFound           = errors.New("transaction not found")
	ErrDenied             = errors.New("transaction denied")
	ErrExpired            = errors.New("transaction expired")
	ErrTimeout            = errors.New("approval timeout")
	ErrSignerNotReady     = errors.New("signer not configured")
	ErrAgentSignData      = errors.New("agent_sign_data required for local-key mode")
	ErrWaitClientMismatch = errors.New("client certificate mismatch")
)

// Store holds in-flight approval transactions.
type Store struct {
	mu        sync.Mutex
	cfg       config.Config
	issuer    signing.CertIssuer
	keySigner *signing.LocalKey
	leases    *lease.Store
	timeout   time.Duration
	txs       map[string]*txEntry
}

type txEntry struct {
	tx       *Transaction
	result   *Result
	resultCh chan Result
	timer    *time.Timer
	waiters  int
}

// NewStore creates a transaction store with the given approval timeout.
func NewStore(timeout time.Duration) *Store {
	return &Store{
		timeout: timeout,
		txs:     make(map[string]*txEntry),
	}
}

// SetConfig applies runtime config (env, timeout) used by Create and dev bypass.
func (s *Store) SetConfig(cfg config.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
	if cfg.ApprovalTimeout > 0 {
		s.timeout = cfg.ApprovalTimeout
	}
}

// SetIssuer configures local CA signing used when SignerMode is local-ca.
func (s *Store) SetIssuer(issuer signing.CertIssuer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issuer = issuer
}

// SetKeySigner configures hosted-key signing used when SignerMode is local-key.
func (s *Store) SetKeySigner(keySigner *signing.LocalKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keySigner = keySigner
}

// SetLeases configures the session lease store used after OOB approval.
func (s *Store) SetLeases(leases *lease.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leases = leases
}

func (s *Store) signerMode() string {
	if s.cfg.SignerMode == SignerModeLocalKey {
		return SignerModeLocalKey
	}
	return SignerModeLocalCA
}

func newTxID() string {
	return "tx_" + ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

// Create registers a pending transaction and returns its metadata and result channel.
// When cfg.Env is "dev", auto-approves via the configured signer.
func (s *Store) Create(targetUser, targetIP, publicKey, sourceIP, clientCertFP, agentSignData, hostKeyFP string, client ClientMeta) (*Transaction, <-chan Result) {
	return s.CreateBound(targetUser, targetIP, publicKey, sourceIP, clientCertFP, agentSignData, hostKeyFP, "", client)
}

// CreateBound registers a transaction bound to a verified destination host key.
func (s *Store) CreateBound(targetUser, targetIP, publicKey, sourceIP, clientCertFP, agentSignData, hostKeyFP, destinationHostKeyFP string, client ClientMeta) (*Transaction, <-chan Result) {
	s.mu.Lock()
	id := newTxID()
	tx := &Transaction{
		ID:                            id,
		TargetUser:                    targetUser,
		TargetIP:                      targetIP,
		PublicKey:                     publicKey,
		SourceIP:                      sourceIP,
		SourceUser:                    client.SourceUser,
		ClientName:                    client.ClientName,
		ClientVersion:                 client.ClientVersion,
		ClientCertFP:                  clientCertFP,
		AgentSignData:                 agentSignData,
		HostKeyFingerprint:            hostKeyFP,
		DestinationHostKeyFingerprint: destinationHostKeyFP,
		DestinationHostKeySource:      client.DestinationHostKeySource,
		DisableLease:                  client.DisableLease,
		State:                         StatePending,
		CreatedAt:                     time.Now(),
	}
	ch := make(chan Result, 1)
	entry := &txEntry{
		tx:       tx,
		resultCh: ch,
	}
	s.txs[id] = entry
	timeout := s.timeout
	cfg := s.cfg
	s.mu.Unlock()

	entry.timer = time.AfterFunc(timeout, func() {
		s.expire(id)
	})

	if cfg.Env == "dev" {
		go s.approveWithIssuer(context.Background(), id, DefaultDevCertTTL, "")
	}

	return tx, ch
}

// Approve marks the transaction approved, issues credentials, and records a session lease.
func (s *Store) Approve(txID string, ttl time.Duration, approverChatID string) {
	if ttl <= 0 {
		ttl = DefaultDevCertTTL
	}
	s.approveWithIssuer(context.Background(), txID, ttl, approverChatID)
}

// IssueFromLease signs immediately when an active session lease matches lookup.
func (s *Store) IssueFromLease(ctx context.Context, lookup lease.LookupKey, publicKey, agentSignData, hostKeyFP string) (Result, bool) {
	s.mu.Lock()
	leases := s.leases
	s.mu.Unlock()
	if leases == nil {
		return Result{}, false
	}
	active, ok := leases.FindActive(lookup)
	if !ok {
		return Result{}, false
	}
	remaining := active.Remaining()
	if remaining <= 0 {
		return Result{}, false
	}
	tx := &Transaction{
		PublicKey:                     publicKey,
		TargetUser:                    lookup.TargetUser,
		TargetIP:                      lookup.TargetIP,
		SourceIP:                      lookup.SourceIP,
		AgentSignData:                 agentSignData,
		HostKeyFingerprint:            hostKeyFP,
		DestinationHostKeyFingerprint: lookup.DestinationHostKeyFingerprint,
	}
	res, err := s.issueForTransaction(ctx, tx, time.Now().Add(remaining))
	if err != nil {
		return Result{Err: err}, false
	}
	res.LeaseExpiresAt = active.ExpiresAt
	return res, true
}

// CreateInstantApproved registers a completed transaction for lease fast-path.
func (s *Store) CreateInstantApproved(targetUser, targetIP, publicKey, sourceIP, clientCertFP string, res Result) *Transaction {
	s.mu.Lock()
	id := newTxID()
	tx := &Transaction{
		ID:           id,
		TargetUser:   targetUser,
		TargetIP:     targetIP,
		PublicKey:    publicKey,
		SourceIP:     sourceIP,
		ClientCertFP: clientCertFP,
		State:        StateApproved,
		CreatedAt:    time.Now(),
	}
	ch := make(chan Result, 1)
	ch <- res
	close(ch)
	s.txs[id] = &txEntry{
		tx:       tx,
		result:   &res,
		resultCh: ch,
	}
	s.mu.Unlock()
	return tx
}

func (s *Store) approveWithIssuer(ctx context.Context, txID string, ttl time.Duration, approverChatID string) {
	entry := s.claimApproval(txID)
	if entry == nil {
		return
	}

	until := time.Now().Add(ttl)
	res, err := s.issueForTransaction(ctx, entry.tx, until)
	if err != nil {
		_ = s.finishClaimed(txID, StateDenied, &Result{Err: err})
		return
	}

	s.mu.Lock()
	leases := s.leases
	s.mu.Unlock()
	leaseExpires := until
	res.LeaseExpiresAt = leaseExpires
	if !s.finishClaimed(txID, StateApproved, &res) {
		return
	}
	if leases != nil && approverChatID != "" && entry.tx.ClientCertFP != "" && !entry.tx.DisableLease {
		lookup := lease.NewLookupKey(
			entry.tx.ClientCertFP,
			entry.tx.TargetUser,
			entry.tx.TargetIP,
			entry.tx.SourceIP,
			entry.tx.HostKeyFingerprint,
			entry.tx.DestinationHostKeyFingerprint,
		)
		leases.Put(lease.NewFullKey(lookup, approverChatID), until)
	}
}

func (s *Store) issueForTransaction(ctx context.Context, tx *Transaction, until time.Time) (Result, error) {
	s.mu.Lock()
	mode := s.signerMode()
	issuer := s.issuer
	keySigner := s.keySigner
	s.mu.Unlock()

	if mode == SignerModeLocalKey {
		if tx.AgentSignData == "" {
			return Result{}, ErrAgentSignData
		}
		if keySigner == nil {
			return Result{}, ErrSignerNotReady
		}
		data, err := base64.StdEncoding.DecodeString(tx.AgentSignData)
		if err != nil {
			return Result{}, err
		}
		hostFP := tx.HostKeyFingerprint
		if hostFP == "" {
			return Result{}, keystore.ErrAmbiguousSigner
		}
		blob, err := keySigner.SignAgent(ctx, hostFP, data)
		if err != nil {
			return Result{}, err
		}
		return Result{
			Signature: base64.StdEncoding.EncodeToString(blob),
			ExpiresAt: until,
		}, nil
	}

	if issuer == nil {
		return Result{}, ErrSignerNotReady
	}
	res, err := issuer.IssueCert(ctx, signing.IssueRequest{
		ClientPubKey: tx.PublicKey,
		TargetUser:   tx.TargetUser,
		TargetIP:     tx.TargetIP,
		SourceIP:     tx.SourceIP,
		ValidUntil:   until,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{
		Cert:      res.Certificate,
		ExpiresAt: res.ExpiresAt,
	}, nil
}

func (s *Store) claimApproval(txID string) *txEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.txs[txID]
	if !ok || entry.result != nil || entry.tx.State != StatePending {
		return nil
	}
	entry.tx.State = StateApproving
	return entry
}

// Snapshot returns a copy of the transaction if it exists (any state).
func (s *Store) Snapshot(txID string) *Transaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.txs[txID]
	if !ok {
		return nil
	}
	cp := *entry.tx
	return &cp
}

// Deny marks the transaction denied and delivers ErrDenied to waiters.
func (s *Store) Deny(txID string) {
	s.finishPending(txID, StateDenied, &Result{Err: ErrDenied})
}

func (s *Store) expire(txID string) {
	s.finishPending(txID, StateExpired, &Result{Err: ErrTimeout})
}

func (s *Store) finishPending(txID string, state State, res *Result) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.txs[txID]
	if !ok || entry.result != nil || entry.tx.State != StatePending {
		return
	}
	s.finishLocked(entry, state, res)
}

func (s *Store) finishClaimed(txID string, state State, res *Result) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.txs[txID]
	if !ok || entry.result != nil || entry.tx.State != StateApproving {
		return false
	}
	s.finishLocked(entry, state, res)
	return true
}

func (s *Store) finishLocked(entry *txEntry, state State, res *Result) {
	entry.tx.State = state
	entry.result = res
	if entry.timer != nil {
		entry.timer.Stop()
	}
	select {
	case entry.resultCh <- *res:
	default:
	}
}

// Wait blocks until the transaction is approved, denied, expires, or ctx is canceled.
func (s *Store) Wait(ctx context.Context, txID string) (cert, signature string, expiresAt, leaseExpiresAt time.Time, err error) {
	res, ok := s.waitResult(ctx, txID)
	if !ok {
		return "", "", time.Time{}, time.Time{}, ErrNotFound
	}

	select {
	case r := <-res.ch:
		s.remove(txID)
		if r.Err != nil {
			return "", "", time.Time{}, time.Time{}, r.Err
		}
		return r.Cert, r.Signature, r.ExpiresAt, r.LeaseExpiresAt, nil
	case <-ctx.Done():
		s.cancelWait(txID)
		return "", "", time.Time{}, time.Time{}, ctx.Err()
	}
}

type waitSlot struct {
	ch <-chan Result
}

func (s *Store) waitResult(ctx context.Context, txID string) (waitSlot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.txs[txID]
	if !ok {
		return waitSlot{}, false
	}
	if entry.result != nil {
		ch := make(chan Result, 1)
		ch <- *entry.result
		close(ch)
		return waitSlot{ch: ch}, true
	}
	entry.waiters++
	return waitSlot{ch: entry.resultCh}, true
}

func (s *Store) cancelWait(txID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.txs[txID]
	if !ok {
		return
	}
	entry.waiters--
	if entry.waiters <= 0 {
		if entry.timer != nil {
			entry.timer.Stop()
		}
		delete(s.txs, txID)
	}
}

func (s *Store) remove(txID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.txs, txID)
}

// ClientCertFP returns the mTLS client cert fingerprint bound to txID.
func (s *Store) ClientCertFP(txID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.txs[txID]
	if !ok {
		return "", false
	}
	return entry.tx.ClientCertFP, true
}
