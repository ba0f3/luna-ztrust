package vault

import (
	"context"
	"errors"
)

// StaticTokenProvider returns a fixed token (tests).
type StaticTokenProvider struct {
	Value string
}

func (p StaticTokenProvider) Token(context.Context) (string, error) {
	return p.Value, nil
}

// Err: production placeholder until vault-agent SO_PEERCRED (task 11).
var ErrTokenProviderUnavailable = errors.New("vault token provider not configured")

// UnavailableTokenProvider always fails; use until SO_PEERCRED token reader exists.
type UnavailableTokenProvider struct{}

func (UnavailableTokenProvider) Token(context.Context) (string, error) {
	return "", ErrTokenProviderUnavailable
}
