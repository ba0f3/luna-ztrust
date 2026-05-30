package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"time"
)

func verifyDeviceSignature(pub ed25519.PublicKey, payload []byte, sigHex string, now time.Time, ts int64) error {
	if ts < now.Unix()-30 || ts > now.Unix()+30 {
		return errTimestampOutOfRange
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errInvalidDeviceSignature
	}
	if !ed25519.Verify(pub, payload, sig) {
		return errInvalidDeviceSignature
	}
	return nil
}

var (
	errTimestampOutOfRange   = errDeviceAuth{msg: "timestamp out of range"}
	errInvalidDeviceSignature = errDeviceAuth{msg: "signature verification failed"}
)

type errDeviceAuth struct {
	msg string
}

func (e errDeviceAuth) Error() string { return e.msg }

func writeDeviceAuthError(w http.ResponseWriter, err error) {
	switch err {
	case errTimestampOutOfRange:
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, err.Error(), http.StatusForbidden)
	}
}
