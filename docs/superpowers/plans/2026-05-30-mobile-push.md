# Mobile push (P5) — follow-on plan

**Status:** Deferred. Server ships `internal/mobile/push.go` with a `Notifier` stub; `FCM_CREDENTIALS` selects the implementation hook but does not call external APIs yet.

## Scope (when implemented)

- FCM (Android) and APNs (iOS) for pending `tx_id` after `POST /api/v1/ssh/sign`
- Idempotency aligned with Telegram (no duplicate effective approvals)
- Device enrollment from P4 (`POST /api/v1/mobile/enroll`)

## Exit criteria

- Staging: manual approve on a physical device after push delivery
- CI: no outbound FCM/APNs calls; unit tests mock `Notifier`

See [self-hosted central design](../specs/2026-05-30-self-hosted-central-design.md) §8.4.
