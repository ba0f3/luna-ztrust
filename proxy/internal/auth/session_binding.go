package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"golang.org/x/crypto/ssh"
)

var ErrInvalidSessionBinding = errors.New("invalid SSH session binding")

// SessionBinding proves the destination host key and SSH exchange hash.
type SessionBinding struct {
	HostPublicKey string `json:"host_public_key"`
	SessionID     string `json:"session_id"`
	Signature     string `json:"signature"`
	Forwarding    bool   `json:"forwarding"`
}

// ValidatedSessionBinding is authoritative context derived from SessionBinding.
type ValidatedSessionBinding struct {
	HostKeyFingerprint string
	SessionID          []byte
}

// ValidateLocalKeySignData verifies an OpenSSH session binding and the
// corresponding public-key user-auth request before hosted-key signing.
func ValidateLocalKeySignData(binding SessionBinding, signData []byte, targetUser string, expectedKey ssh.PublicKey) (ValidatedSessionBinding, error) {
	if binding.Forwarding {
		return ValidatedSessionBinding{}, fmt.Errorf("%w: forwarding is not allowed", ErrInvalidSessionBinding)
	}
	hostWire, err := decodeRequiredBase64(binding.HostPublicKey)
	if err != nil {
		return ValidatedSessionBinding{}, fmt.Errorf("%w: host public key", ErrInvalidSessionBinding)
	}
	hostKey, err := ssh.ParsePublicKey(hostWire)
	if err != nil {
		return ValidatedSessionBinding{}, fmt.Errorf("%w: host public key", ErrInvalidSessionBinding)
	}
	sessionID, err := decodeRequiredBase64(binding.SessionID)
	if err != nil {
		return ValidatedSessionBinding{}, fmt.Errorf("%w: session id", ErrInvalidSessionBinding)
	}
	sigWire, err := decodeRequiredBase64(binding.Signature)
	if err != nil {
		return ValidatedSessionBinding{}, fmt.Errorf("%w: signature", ErrInvalidSessionBinding)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigWire, &sig); err != nil {
		return ValidatedSessionBinding{}, fmt.Errorf("%w: signature", ErrInvalidSessionBinding)
	}
	if err := hostKey.Verify(sessionID, &sig); err != nil {
		return ValidatedSessionBinding{}, fmt.Errorf("%w: signature", ErrInvalidSessionBinding)
	}
	if err := validateUserAuthSignData(signData, sessionID, targetUser, expectedKey, hostKey); err != nil {
		return ValidatedSessionBinding{}, err
	}
	return ValidatedSessionBinding{
		HostKeyFingerprint: keystore.Fingerprint(hostKey),
		SessionID:          append([]byte(nil), sessionID...),
	}, nil
}

// ValidateDirectLocalKeySignData validates user-auth data from an in-process
// SSH client and derives the destination from the host key accepted by its
// HostKeyCallback. Unlike OpenSSH session binding, this is a client assertion.
func ValidateDirectLocalKeySignData(hostPublicKey string, signData []byte, targetUser string, expectedKey ssh.PublicKey) (ValidatedSessionBinding, error) {
	hostWire, err := decodeRequiredBase64(hostPublicKey)
	if err != nil {
		return ValidatedSessionBinding{}, fmt.Errorf("%w: destination host public key", ErrInvalidSessionBinding)
	}
	hostKey, err := ssh.ParsePublicKey(hostWire)
	if err != nil {
		return ValidatedSessionBinding{}, fmt.Errorf("%w: destination host public key", ErrInvalidSessionBinding)
	}
	sessionID, err := validateDirectUserAuthSignData(signData, targetUser, expectedKey, hostKey)
	if err != nil {
		return ValidatedSessionBinding{}, err
	}
	return ValidatedSessionBinding{
		HostKeyFingerprint: keystore.Fingerprint(hostKey),
		SessionID:          sessionID,
	}, nil
}

func validateUserAuthSignData(data, expectedSessionID []byte, targetUser string, expectedKey, boundHostKey ssh.PublicKey) error {
	req, err := parseUserAuthSignData(data)
	if err != nil {
		return err
	}
	if !bytes.Equal(req.SessionID, expectedSessionID) {
		return fmt.Errorf("%w: user-auth request mismatch", ErrInvalidSessionBinding)
	}
	return validateParsedUserAuth(req, targetUser, expectedKey, boundHostKey)
}

func validateDirectUserAuthSignData(data []byte, targetUser string, expectedKey, hostKey ssh.PublicKey) ([]byte, error) {
	req, err := parseUserAuthSignData(data)
	if err != nil {
		return nil, err
	}
	if err := validateParsedUserAuth(req, targetUser, expectedKey, hostKey); err != nil {
		return nil, err
	}
	return append([]byte(nil), req.SessionID...), nil
}

type userAuthSignData struct {
	SessionID []byte
	User      string `sshtype:"50"`
	Service   string
	Method    string
	HasSig    bool
	Algorithm string
	PublicKey []byte
	Rest      []byte `ssh:"rest"`
}

func parseUserAuthSignData(data []byte) (userAuthSignData, error) {
	if len(data) == 0 {
		return userAuthSignData{}, fmt.Errorf("%w: missing sign data", ErrInvalidSessionBinding)
	}
	var req userAuthSignData
	if err := ssh.Unmarshal(data, &req); err != nil {
		return userAuthSignData{}, fmt.Errorf("%w: user-auth request", ErrInvalidSessionBinding)
	}
	if len(req.SessionID) == 0 {
		return userAuthSignData{}, fmt.Errorf("%w: missing session id", ErrInvalidSessionBinding)
	}
	return req, nil
}

func validateParsedUserAuth(req userAuthSignData, targetUser string, expectedKey, boundHostKey ssh.PublicKey) error {
	if expectedKey == nil || req.User != targetUser || req.Service != "ssh-connection" || !req.HasSig ||
		req.Algorithm != expectedKey.Type() || !bytes.Equal(req.PublicKey, expectedKey.Marshal()) {
		return fmt.Errorf("%w: user-auth request mismatch", ErrInvalidSessionBinding)
	}
	switch req.Method {
	case "publickey":
		if len(req.Rest) != 0 {
			return fmt.Errorf("%w: trailing user-auth data", ErrInvalidSessionBinding)
		}
	case "publickey-hostbound-v00@openssh.com":
		var hostbound struct {
			HostKey []byte
		}
		if err := ssh.Unmarshal(req.Rest, &hostbound); err != nil || !bytes.Equal(hostbound.HostKey, boundHostKey.Marshal()) {
			return fmt.Errorf("%w: host-bound key mismatch", ErrInvalidSessionBinding)
		}
	default:
		return fmt.Errorf("%w: unsupported user-auth method", ErrInvalidSessionBinding)
	}
	return nil
}

func decodeRequiredBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("required")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, errors.New("invalid base64")
	}
	return b, nil
}
