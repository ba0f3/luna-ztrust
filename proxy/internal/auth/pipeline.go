package auth

import (
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

const timestampWindowSec = 30

// ErrReplay is returned when the same request body was seen within the replay TTL.
var ErrReplay = errors.New("replay detected")

// ErrInvalidPoP is returned when proof-of-possession verification fails.
var ErrInvalidPoP = errors.New("invalid proof of possession")

// SignRequest is the JSON body for POST /api/v1/ssh/sign.
type SignRequest struct {
	PublicKey     string `json:"public_key"`
	TargetUser    string `json:"target_user"`
	TargetIP      string `json:"target_ip"`
	Timestamp     int64  `json:"timestamp"`
	PopSignature  string `json:"pop_signature"`
	AgentSignData string `json:"agent_sign_data,omitempty"`
	BodyMAC       string `json:"-"` // X-Luna-Body-Mac header, set by handler
}

// ValidateSignRequest runs HMAC, timestamp, replay, and PoP checks in that order.
func ValidateSignRequest(conn *tls.Conn, rawBody []byte, req *SignRequest, now time.Time, replay *ReplayLRU) error {
	if err := VerifyBodyHMAC(conn, rawBody, req.BodyMAC); err != nil {
		return err
	}
	if err := ValidateTimestampAt(req.Timestamp, now, timestampWindowSec); err != nil {
		return err
	}
	sum := sha256.Sum256(rawBody)
	if !replay.AddIfNew(sum[:]) {
		return ErrReplay
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return fmt.Errorf("public_key: %w", err)
	}
	if err := VerifyPoP(pub, req.TargetUser, req.TargetIP, req.Timestamp, req.PopSignature); err != nil {
		return ErrInvalidPoP
	}
	return nil
}

// ValidateTimestampAt checks that ts is within ±windowSec of now.
func ValidateTimestampAt(ts int64, now time.Time, windowSec int) error {
	ref := now.Unix()
	delta := ref - ts
	if delta < 0 {
		delta = -delta
	}
	if delta > int64(windowSec) {
		return ErrTimestampOutsideWindow
	}
	return nil
}
