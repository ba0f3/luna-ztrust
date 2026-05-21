package approval

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
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
	mu      sync.Mutex
	cfg     config.Config
	timeout time.Duration
	txs     map[string]*txEntry
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

func newTxID() string {
	return "tx_" + ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

// Create registers a pending transaction and returns its metadata and result channel.
// When cfg.Env is "dev", the transaction is auto-approved with placeholder cert "dev-cert".
func (s *Store) Create(targetUser, targetIP string) (*Transaction, <-chan Result) {
	s.mu.Lock()
	id := newTxID()
	tx := &Transaction{
		ID:         id,
		TargetUser: targetUser,
		TargetIP:   targetIP,
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
	s.mu.Unlock()

	entry.timer = time.AfterFunc(timeout, func() {
		s.expire(id)
	})

	if cfg.Env == "dev" {
		go s.Approve(id, "dev-cert")
	}

	return tx, ch
}

// Approve marks the transaction approved and delivers certPEM to waiters.
func (s *Store) Approve(txID, certPEM string) {
	s.finish(txID, StateApproved, &Result{Cert: certPEM})
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
