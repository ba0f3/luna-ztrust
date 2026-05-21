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

// ErrTokenProviderUnavailable is returned when no vault token source is configured.
var ErrTokenProviderUnavailable = errors.New("vault token provider not configured")

// UnavailableTokenProvider always fails; use when VAULT_AGENT_SOCKET is unset.
type UnavailableTokenProvider struct{}

func (UnavailableTokenProvider) Token(context.Context) (string, error) {
	return "", ErrTokenProviderUnavailable
}
