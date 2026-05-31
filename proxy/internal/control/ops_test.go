package control

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/cli"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/mobile"
	"golang.org/x/crypto/ssh"
)

const testPassphrase = "test-pass"

func testServer(t *testing.T, signerMode string) *Server {
	t.Helper()
	var ks *keystore.Keystore
	if signerMode == approval.SignerModeLocalKey {
		ks = keystore.NewWithMode(keystore.ModeLocalKey)
	} else {
		ks = keystore.New()
	}
	return NewServer(ServerDeps{
		Config:   config.Config{SignerMode: signerMode},
		Keystore: ks,
		Mobile:   mobile.NewStore(),
		Pending:  keystore.NewPendingStore(),
	})
}

func writeEncryptedKeyFile(t *testing.T, path string) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "luna-test", []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	return pemBytes
}

func reqData(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHandleStatusSealed(t *testing.T) {
	s := testServer(t, approval.SignerModeLocalCA)
	resp := s.handle(Request{Op: "status", ID: "1"})
	if !resp.OK {
		t.Fatalf("status: %+v", resp)
	}
	var data struct {
		Sealed bool `json:"sealed"`
	}
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatal(err)
	}
	if !data.Sealed {
		t.Fatal("expected sealed")
	}
}

func TestHandleKeyLoadAndList(t *testing.T) {
	s := testServer(t, approval.SignerModeLocalCA)
	path := filepath.Join(t.TempDir(), "encrypted.key")
	writeEncryptedKeyFile(t, path)

	load := s.handle(Request{
		Op:   "key.load",
		ID:   "2",
		Data: reqData(t, map[string]string{"path": path, "passphrase": testPassphrase}),
	})
	if !load.OK {
		t.Fatalf("key.load: %+v", load)
	}

	list := s.handle(Request{Op: "key.list", ID: "3"})
	if !list.OK {
		t.Fatalf("key.list: %+v", list)
	}
	var listed struct {
		Signers []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"signers"`
	}
	if err := json.Unmarshal(list.Data, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Signers) != 1 {
		t.Fatalf("signers = %d, want 1", len(listed.Signers))
	}

	status := s.handle(Request{Op: "status", ID: "4"})
	var st struct {
		Sealed bool `json:"sealed"`
	}
	_ = json.Unmarshal(status.Data, &st)
	if st.Sealed {
		t.Fatal("expected unsealed after load")
	}
}

func TestHandleKeyLoadBadPassphrase(t *testing.T) {
	s := testServer(t, approval.SignerModeLocalCA)
	path := filepath.Join(t.TempDir(), "encrypted.key")
	writeEncryptedKeyFile(t, path)

	resp := s.handle(Request{
		Op:   "key.load",
		ID:   "x",
		Data: reqData(t, map[string]string{"path": path, "passphrase": "wrong"}),
	})
	if resp.OK {
		t.Fatal("expected failure")
	}
	if resp.Code != "FORBIDDEN" {
		t.Fatalf("code = %q", resp.Code)
	}
}

func TestHandleKeyRemove(t *testing.T) {
	s := testServer(t, approval.SignerModeLocalKey)
	path := filepath.Join(t.TempDir(), "encrypted.key")
	writeEncryptedKeyFile(t, path)

	load := s.handle(Request{
		Op:   "key.load",
		Data: reqData(t, map[string]string{"path": path, "passphrase": testPassphrase}),
	})
	if !load.OK {
		t.Fatal(load.Error)
	}
	var fpOut struct {
		Fingerprint string `json:"fingerprint"`
	}
	_ = json.Unmarshal(load.Data, &fpOut)

	remove := s.handle(Request{
		Op:   "key.remove",
		Data: reqData(t, map[string]string{"fingerprint": fpOut.Fingerprint}),
	})
	if !remove.OK {
		t.Fatalf("remove: %+v", remove)
	}
	if s.deps.Keystore.Available() {
		t.Fatal("pool should be empty after remove")
	}
}

func TestHandleKeyConfirmAndReject(t *testing.T) {
	s := testServer(t, approval.SignerModeLocalKey)
	pemBytes := writeEncryptedKeyFile(t, filepath.Join(t.TempDir(), "unused.key"))

	pendID, err := s.deps.Pending.Add("dev_test", "label", "comment", pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	reject := s.handle(Request{
		Op:   "key.reject",
		Data: reqData(t, map[string]string{"pending_id": pendID}),
	})
	if !reject.OK {
		t.Fatalf("reject: %+v", reject)
	}
	if _, err := s.deps.Pending.Get(pendID); !errors.Is(err, keystore.ErrPendingNotFound) {
		t.Fatalf("pending get after reject: %v", err)
	}

	pendID2, err := s.deps.Pending.Add("dev_test", "label2", "", pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	confirm := s.handle(Request{
		Op:   "key.confirm",
		Data: reqData(t, map[string]string{"pending_id": pendID2, "passphrase": testPassphrase}),
	})
	if !confirm.OK {
		t.Fatalf("confirm: %+v", confirm)
	}
	if !s.deps.Keystore.Available() {
		t.Fatal("expected key loaded after confirm")
	}
}

func TestHandleKeyConfirmRequiresLocalKeyMode(t *testing.T) {
	s := testServer(t, approval.SignerModeLocalCA)
	resp := s.handle(Request{
		Op:   "key.confirm",
		Data: reqData(t, map[string]string{"pending_id": "pend_x", "passphrase": testPassphrase}),
	})
	if resp.OK || resp.Code != "BAD_REQUEST" {
		t.Fatalf("confirm: %+v", resp)
	}
}

func TestHandleKeyPendingList(t *testing.T) {
	s := testServer(t, approval.SignerModeLocalKey)
	pemBytes := writeEncryptedKeyFile(t, filepath.Join(t.TempDir(), "k.key"))
	if _, err := s.deps.Pending.Add("dev1", "l", "", pemBytes); err != nil {
		t.Fatal(err)
	}
	resp := s.handle(Request{Op: "key.pending.list", ID: "p"})
	if !resp.OK {
		t.Fatalf("pending.list: %+v", resp)
	}
	var data struct {
		Pending []struct {
			ID string `json:"id"`
		} `json:"pending"`
	}
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Pending) != 1 {
		t.Fatalf("pending = %d", len(data.Pending))
	}
}

func TestHandleMobileEnrollListDelete(t *testing.T) {
	s := testServer(t, approval.SignerModeLocalCA)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))

	enroll := s.handle(Request{
		Op:   "mobile.enroll",
		Data: reqData(t, map[string]string{"label": "phone", "device_pubkey": pubB64}),
	})
	if !enroll.OK {
		t.Fatalf("enroll: %+v", enroll)
	}
	var dev struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(enroll.Data, &dev); err != nil {
		t.Fatal(err)
	}

	list := s.handle(Request{Op: "mobile.list"})
	if !list.OK {
		t.Fatalf("list: %+v", list)
	}

	del := s.handle(Request{
		Op:   "mobile.delete",
		Data: reqData(t, map[string]string{"device_id": dev.DeviceID}),
	})
	if !del.OK {
		t.Fatalf("delete: %+v", del)
	}
}

func TestHandleUnknownOp(t *testing.T) {
	s := testServer(t, approval.SignerModeLocalCA)
	resp := s.handle(Request{Op: "nope", ID: "z"})
	if resp.OK || resp.Code != "UNKNOWN" {
		t.Fatalf("resp: %+v", resp)
	}
}

func testCLIServer(t *testing.T) *Server {
	t.Helper()
	caCert, caKey := loadControlTestCA(t)
	signer := cli.NewCSRSigner(caCert, caKey, "luna-cli", 24*time.Hour)
	return NewServer(ServerDeps{
		Config:    config.Config{SignerMode: approval.SignerModeLocalCA},
		Keystore:  keystore.New(),
		Mobile:    mobile.NewStore(),
		Pending:   keystore.NewPendingStore(),
		Cli:       cli.NewStore(),
		CSRSigner: signer,
	})
}

func loadControlTestCA(t *testing.T) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "testdata", "ca")

	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("no certificate block in ca.crt")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("no key block in ca.key")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return caCert, caKey
}

func generateControlTestCSR(t *testing.T, ou string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			OrganizationalUnit: []string{ou},
			CommonName:         "Luna CLI Test",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

func TestHandleCLIEnrollListDelete(t *testing.T) {
	s := testCLIServer(t)
	csrPEM := generateControlTestCSR(t, "luna-cli")

	enroll := s.handle(Request{
		Op:   "cli.enroll",
		ID:   "c1",
		Data: reqData(t, map[string]string{"label": "laptop", "csr_pem": string(csrPEM)}),
	})
	if !enroll.OK {
		t.Fatalf("cli.enroll: %+v", enroll)
	}
	var enrolled struct {
		DeviceID       string `json:"device_id"`
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(enroll.Data, &enrolled); err != nil {
		t.Fatal(err)
	}
	if enrolled.DeviceID == "" || enrolled.CertificatePEM == "" {
		t.Fatalf("enroll data: %+v", enrolled)
	}

	list := s.handle(Request{Op: "cli.list", ID: "c2"})
	if !list.OK {
		t.Fatalf("cli.list: %+v", list)
	}
	var listed struct {
		Devices []struct {
			DeviceID string `json:"device_id"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(list.Data, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Devices) != 1 || listed.Devices[0].DeviceID != enrolled.DeviceID {
		t.Fatalf("devices = %+v", listed.Devices)
	}

	del := s.handle(Request{
		Op:   "cli.delete",
		ID:   "c3",
		Data: reqData(t, map[string]string{"device_id": enrolled.DeviceID}),
	})
	if !del.OK {
		t.Fatalf("cli.delete: %+v", del)
	}

	listAfter := s.handle(Request{Op: "cli.list", ID: "c4"})
	var after struct {
		Devices []any `json:"devices"`
	}
	_ = json.Unmarshal(listAfter.Data, &after)
	if len(after.Devices) != 0 {
		t.Fatalf("devices after delete = %d", len(after.Devices))
	}
}

func TestHandleCLIEnrollRequiresCSRSigner(t *testing.T) {
	s := NewServer(ServerDeps{
		Config:   config.Config{SignerMode: approval.SignerModeLocalCA},
		Keystore: keystore.New(),
		Mobile:   mobile.NewStore(),
		Pending:  keystore.NewPendingStore(),
		Cli:      cli.NewStore(),
	})
	resp := s.handle(Request{
		Op:   "cli.enroll",
		Data: reqData(t, map[string]string{"label": "x", "csr_pem": "pem"}),
	})
	if resp.OK || resp.Code != "UNAVAILABLE" {
		t.Fatalf("enroll without signer: %+v", resp)
	}
}
