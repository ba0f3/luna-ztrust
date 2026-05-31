package keystore_test

import (
	"path/filepath"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
)

func TestKeystore_LocalKeyPool_GetByFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "encrypted.key")
	writeEncryptedKeyFile(t, path)

	ks := keystore.NewWithMode(keystore.ModeLocalKey)
	fp, err := ks.LoadPEMFile(path, testPassphrase, "deploy")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if fp == "" {
		t.Fatal("empty fingerprint")
	}
	signer, err := ks.SignerForFingerprint(fp)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if signer == nil {
		t.Fatal("nil signer")
	}
	list := ks.ListSigners()
	if len(list) != 1 || list[0].Fingerprint != fp {
		t.Fatalf("list = %+v", list)
	}
}

func TestKeystore_SSHSignerRejectsLocalKeyMode(t *testing.T) {
	ks := keystore.NewWithMode(keystore.ModeLocalKey)
	_, err := ks.SSHSigner()
	if err == nil {
		t.Fatal("expected error")
	}
}
