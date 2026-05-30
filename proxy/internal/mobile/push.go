package mobile

import (
	"context"
	"errors"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
)

// ErrPushNotConfigured is returned when FCM/APNs credentials are not set.
var ErrPushNotConfigured = errors.New("mobile push not configured")

// Notifier delivers pending-transaction alerts to enrolled devices (P5).
type Notifier interface {
	NotifyPending(ctx context.Context, tx *approval.Transaction) error
}

// StubNotifier is the default until FCM_CREDENTIALS is wired (phase P5).
type StubNotifier struct{}

// NotifyPending reports that push is not configured.
func (StubNotifier) NotifyPending(context.Context, *approval.Transaction) error {
	return ErrPushNotConfigured
}

// NewPushNotifier returns a push notifier when credentials are present.
func NewPushNotifier(fcmCredentials string) Notifier {
	if fcmCredentials == "" {
		return StubNotifier{}
	}
	// P5: return real FCM/APNs implementation.
	return StubNotifier{}
}
