//go:build linux

package keystore

import (
	"crypto/ed25519"
	"fmt"
	"reflect"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func mlockSigner(signer ssh.Signer) error {
	if signer == nil {
		return fmt.Errorf("nil signer")
	}
	v := reflect.ValueOf(signer)
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return fmt.Errorf("nil signer")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("unsupported signer representation %T", signer)
	}
	for _, name := range []string{"key", "Key"} {
		f := v.FieldByName(name)
		if !f.IsValid() || f.Type() != reflect.TypeOf(ed25519.PrivateKey(nil)) {
			continue
		}
		if f.CanInterface() {
			return mlockBytes(f.Interface().(ed25519.PrivateKey))
		}
		if f.CanAddr() {
			pk := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Interface().(ed25519.PrivateKey)
			return mlockBytes(pk)
		}
	}
	return fmt.Errorf("private key memory not found in signer %T", signer)
}

func mlockBytes(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if err := unix.Mlock(b); err != nil {
		return fmt.Errorf("mlock sensitive memory: %w", err)
	}
	return nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
