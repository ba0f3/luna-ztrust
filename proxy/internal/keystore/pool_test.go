package keystore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"golang.org/x/crypto/ssh"
)

func TestLocalKeyPool_AddListRemove(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	fp := keystore.Fingerprint(signer.PublicKey())

	pool := keystore.NewLocalKeyPool()
	if pool.Available() {
		t.Fatal("empty pool should not be available")
	}
	gotFP, err := pool.Add(signer, "test")
	if err != nil {
		t.Fatal(err)
	}
	if gotFP != fp {
		t.Fatalf("fp = %q want %q", gotFP, fp)
	}
	list := pool.List()
	if len(list) != 1 || list[0].Fingerprint != fp {
		t.Fatalf("list = %+v", list)
	}
	got, err := pool.Get(fp)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKey().Type() != signer.PublicKey().Type() {
		t.Fatal("signer mismatch")
	}
	if err := pool.Remove(fp); err != nil {
		t.Fatal(err)
	}
	if pool.Available() {
		t.Fatal("pool should be empty")
	}
	_, err = pool.Get(fp)
	if err == nil {
		t.Fatal("expected error after remove")
	}
}
