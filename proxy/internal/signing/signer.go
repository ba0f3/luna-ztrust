package signing

import (
	"context"
	"time"
)

// IssueRequest holds inputs for issuing an SSH user certificate.
type IssueRequest struct {
	ClientPubKey string
	TargetUser   string
	TargetIP     string
	SourceIP     string
	ValidUntil   time.Time
}

// IssueResult is a signed SSH certificate and its validity end time.
type IssueResult struct {
	Certificate string
	ExpiresAt   time.Time
}

// CertIssuer signs short-lived SSH user certificates.
type CertIssuer interface {
	IssueCert(ctx context.Context, req IssueRequest) (IssueResult, error)
}
