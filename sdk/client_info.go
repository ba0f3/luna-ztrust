package sdk

import "github.com/ba0f3/luna-ztrust/sdk/sign"

// ClientInfo is optional metadata sent with sign requests (approval display and audit logs).
// It is not included in the PoP challenge; the proxy still derives authoritative source IP from mTLS RemoteAddr.
type ClientInfo = sign.ClientInfo
