package approval

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/vault"
	"github.com/oklog/ulid/v2"
)

// State is the approval transaction lifecycle state.
type State string

const (
	StatePending  State = "pending"
	StateApproved State = "approved"
	StateDenied   State = "denied"
	StateExpired  State = "expired"
)

// Transaction is a pending or terminal SSH sign approval request.
type Transaction struct {
	ID         string
	TargetUser string
	TargetIP   string
	PublicKey  string
	State      State
	CreatedAt  time.Time
}

// Result is delivered to waiters when a transaction reaches a terminal state.
type Result struct {
	Cert string
	Err  error
}

var (
	ErrNotFound = errors.New("transaction not found")
	ErrDenied   = errors.New("transaction denied")
	ErrExpired  = errors.New("transaction expired")
	ErrTimeout  = errors.New("approval timeout")
)

// Store holds in-flight approval transactions.
type Store struct {
	mu       sync.Mutex
	cfg      config.Config
	vaultCfg vault.SignConfig
	tokens   vault.TokenProvider
	timeout  time.Duration
	txs      map[string]*txEntry
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

// SetVault configures Vault SSH signing used when Approve is called and VaultAddr is set.
func (s *Store) SetVault(cfg vault.SignConfig, tokens vault.TokenProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vaultCfg = cfg
	s.tokens = tokens
}

func newTxID() string {
	return "tx_" + ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

// Create registers a pending transaction and returns its metadata and result channel.
// When cfg.Env is "dev" and VaultAddr is unset, auto-approves with placeholder cert "dev-cert".
func (s *Store) Create(targetUser, targetIP, publicKey string) (*Transaction, <-chan Result) {
	s.mu.Lock()
	id := newTxID()
	tx := &Transaction{
		ID:         id,
		TargetUser: targetUser,
		TargetIP:   targetIP,
		PublicKey:  publicKey,
		State:      StatePending,
		CreatedAt:  time.Now(),
	}
	ch := make(chan Result, 1)
	entry := &txEntry{
		tx:       tx,
		resultCh: ch,
	}
	s.txs[id] = entry
	timeout := s.timeout
	cfg := s.cfg
	vaultAddr := s.vaultCfg.VaultAddr
	s.mu.Unlock()

	entry.timer = time.AfterFunc(timeout, func() {
		s.expire(id)
	})

	if cfg.Env == "dev" {
		if vaultAddr != "" {
			go s.approveViaVault(context.Background(), id)
		} else {
			go s.Approve(id, "dev-cert")
		}
	}

	return tx, ch
}

// Approve marks the transaction approved and delivers certPEM to waiters.
// When VaultAddr is configured, certPEM is ignored and the cert is obtained from Vault.
func (s *Store) Approve(txID, certPEM string) {
	s.mu.Lock()
	vaultAddr := s.vaultCfg.VaultAddr
	s.mu.Unlock()
	if vaultAddr != "" {
		s.approveViaVault(context.Background(), txID)
		return
	}
	s.finish(txID, StateApproved, &Result{Cert: certPEM})
}

func (s *Store) approveViaVault(ctx context.Context, txID string) {
	entry := s.getEntry(txID)
	if entry == nil {
		return
	}
	if s.tokens == nil {
		s.finish(txID, StateDenied, &Result{Err: vault.ErrTokenProviderUnavailable})
		return
	}
	token, err := s.tokens.Token(ctx)
	if err != nil {
		s.finish(txID, StateDenied, &Result{Err: err})
		return
	}
	cert, err := vault.SignSSHKey(ctx, s.vaultCfg, token, entry.tx.PublicKey, entry.tx.TargetUser, entry.tx.TargetIP)
	if err != nil {
		s.finish(txID, StateDenied, &Result{Err: err})
		return
	}
	s.finish(txID, StateApproved, &Result{Cert: cert})
}

func (s *Store) getEntry(txID string) *txEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.txs[txID]
	if !ok || entry.result != nil {
		return nil
	}
	return entry
}

// Deny marks the transaction denied and delivers ErrDenied to waiters.
func (s *Store) Deny(txID string) {
	s.finish(txID, StateDenied, &Result{Err: ErrDenied})
}

func (s *Store) expire(txID string) {
	s.finish(txID, StateExpired, &Result{Err: ErrTimeout})
}

func (s *Store) finish(txID string, state State, res *Result) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.txs[txID]
	if !ok || entry.result != nil {
		return
	}
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
// On context cancellation the transaction is removed from the store.
func (s *Store) Wait(ctx context.Context, txID string) (string, error) {
	res, ok := s.waitResult(ctx, txID)
	if !ok {
		return "", ErrNotFound
	}

	select {
	case r := <-res.ch:
		s.remove(txID)
		if r.Err != nil {
			return "", r.Err
		}
		return r.Cert, nil
	case <-ctx.Done():
		s.cancelWait(txID)
		return "", ctx.Err()
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
