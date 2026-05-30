//go:build linux

package keystore

import (
	"crypto/ed25519"
	"reflect"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func mlockSigner(signer ssh.Signer) {
	if signer == nil {
		return
	}
	v := reflect.ValueOf(signer)
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	for _, name := range []string{"key", "Key"} {
		f := v.FieldByName(name)
		if !f.IsValid() || f.Type() != reflect.TypeOf(ed25519.PrivateKey(nil)) {
			continue
		}
		if f.CanInterface() {
			mlockBytes(f.Interface().(ed25519.PrivateKey))
			return
		}
		if f.CanAddr() {
			pk := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Interface().(ed25519.PrivateKey)
			mlockBytes(pk)
			return
		}
	}
}

func mlockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = unix.Mlock(b)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
