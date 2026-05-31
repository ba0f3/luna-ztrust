package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ba0f3/luna-ztrust/proxy/internal/cli/httpclient"
	"github.com/ba0f3/luna-ztrust/proxy/internal/control/client"
	"github.com/spf13/cobra"
)

const (
	cliKeyFile  = "cli.key"
	cliCSRFile  = "cli.csr.pem"
	cliCertFile = "cli.crt"
	cliClientOU = "luna-cli"
)

var (
	cliDir             string
	cliForce           bool
	cliLabel           string
	cliCSRPath         string
	cliCertPath        string
	cliEnrollAdminCert string
	cliEnrollAdminKey  string
)

var cliCmd = &cobra.Command{
	Use:   "cli",
	Short: "Manage enrolled CLI operator devices",
}

var cliInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a local CLI RSA private key",
	RunE:  runCLIInit,
}

var cliCSRCmd = &cobra.Command{
	Use:   "csr",
	Short: "Create a certificate signing request from cli.key",
	RunE:  runCLICSR,
}

var cliEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll a CLI device (control socket on-host, or admin mTLS over HTTP)",
	RunE:  runCLIEnroll,
}

var cliListCmd = &cobra.Command{
	Use:   "list",
	Short: "List enrolled CLI devices",
	RunE:  runCLIList,
}

var cliDeleteCmd = &cobra.Command{
	Use:   "delete [device-id]",
	Short: "Delete an enrolled CLI device",
	Args:  cobra.ExactArgs(1),
	RunE:  runCLIDelete,
}

func init() {
	cliInitCmd.Flags().StringVar(&cliDir, "dir", "", "CLI config directory (default ~/.config/luna)")
	cliInitCmd.Flags().BoolVar(&cliForce, "force", false, "overwrite existing cli.key")

	cliCSRCmd.Flags().StringVar(&cliDir, "dir", "", "CLI config directory (default ~/.config/luna)")

	cliEnrollCmd.Flags().StringVar(&cliLabel, "label", "", "device label")
	cliEnrollCmd.Flags().StringVar(&cliCSRPath, "csr-file", "", "path to CSR PEM file")
	cliEnrollCmd.Flags().StringVar(&cliCertPath, "cert-out", "", "path for issued client certificate (default cli.crt next to csr-file or in cwd)")
	cliEnrollCmd.Flags().StringVar(&keyLoadProxyURL, "proxy-url", "", "proxy HTTPS base URL for remote enroll (admin mTLS)")
	cliEnrollCmd.Flags().StringVar(&cliEnrollAdminCert, "admin-cert", "", "admin client certificate (OU=luna-admin)")
	cliEnrollCmd.Flags().StringVar(&cliEnrollAdminKey, "admin-key", "", "admin client private key")
	cliEnrollCmd.Flags().StringVar(&keyLoadCA, "ca", "", "mTLS CA certificate (optional; downloaded from GET /api/v1/mtls/ca)")
	_ = cliEnrollCmd.MarkFlagRequired("label")
	_ = cliEnrollCmd.MarkFlagRequired("csr-file")

	cliCmd.AddCommand(cliInitCmd, cliCSRCmd, cliEnrollCmd, cliListCmd, cliDeleteCmd)
	rootCmd.AddCommand(cliCmd)
}

func runCLIInit(_ *cobra.Command, _ []string) error {
	dir, err := resolveCLIDir(cliDir)
	if err != nil {
		return err
	}
	keyPath := filepath.Join(dir, cliKeyFile)
	if _, err := os.Stat(keyPath); err == nil && !cliForce {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return os.WriteFile(keyPath, pemBytes, 0o600)
}

func runCLICSR(_ *cobra.Command, _ []string) error {
	dir, err := resolveCLIDir(cliDir)
	if err != nil {
		return err
	}
	key, err := loadCLIKey(filepath.Join(dir, cliKeyFile))
	if err != nil {
		return err
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			OrganizationalUnit: []string{cliClientOU},
			CommonName:         "Luna CLI",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return os.WriteFile(filepath.Join(dir, cliCSRFile), csrPEM, 0o644)
}

func runCLIEnroll(cmd *cobra.Command, _ []string) error {
	csrPEM, err := os.ReadFile(cliCSRPath)
	if err != nil {
		return err
	}

	prof, err := resolveCLIProfile(cmd)
	if err != nil {
		return err
	}
	if prof != nil {
		ctx := context.Background()
		prof.applyAdminDefaults(cliCSRPath)
		if err := prof.validateAdminEnroll(); err != nil {
			return err
		}
		if err := prof.ensureProfileCA(ctx); err != nil {
			return fmt.Errorf("fetch CA: %w", err)
		}
		out, err := httpclient.Enroll(ctx, httpclient.MTLSConfig{
			ProxyURL: prof.ProxyURL,
			Cert:     prof.AdminCert,
			Key:      prof.AdminKey,
			CA:       prof.CA,
		}, cliLabel, string(csrPEM))
		if err != nil {
			return err
		}
		certOut := cliCertPath
		if certOut == "" {
			certOut = defaultCLICertOut(cliCSRPath)
		}
		if err := os.WriteFile(certOut, []byte(out.CertificatePEM), 0o644); err != nil {
			return err
		}
		fmt.Println(out.DeviceID)
		return nil
	}

	path, err := resolveSocket()
	if err != nil {
		return fmt.Errorf("use --proxy-url with admin mTLS for remote enroll, or run on the proxy host with control socket access: %w", err)
	}
	data, err := client.Call(path, "cli.enroll", map[string]string{
		"label":   cliLabel,
		"csr_pem": string(csrPEM),
	})
	if err != nil {
		return err
	}

	var out struct {
		DeviceID       string `json:"device_id"`
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	if out.DeviceID == "" || out.CertificatePEM == "" {
		return errors.New("enroll response missing device_id or certificate_pem")
	}

	certOut := cliCertPath
	if certOut == "" {
		certOut = defaultCLICertOut(cliCSRPath)
	}
	if err := os.WriteFile(certOut, []byte(out.CertificatePEM), 0o644); err != nil {
		return err
	}
	fmt.Println(out.DeviceID)
	return nil
}

func runCLIList(_ *cobra.Command, _ []string) error {
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	data, err := client.Call(path, "cli.list", nil)
	if err != nil {
		return err
	}
	return printCLIListResult(data)
}

func runCLIDelete(_ *cobra.Command, args []string) error {
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	_, err = client.Call(path, "cli.delete", map[string]string{"device_id": args[0]})
	return err
}

func resolveCLIDir(flagDir string) (string, error) {
	if flagDir != "" {
		return flagDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "luna"), nil
}

func defaultCLICertOut(csrFile string) string {
	dir := filepath.Dir(csrFile)
	if dir == "" || dir == "." {
		return cliCertFile
	}
	return filepath.Join(dir, cliCertFile)
}

func loadCLIKey(path string) (*rsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("read %s: no PEM block", path)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("read %s: expected RSA private key", path)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("read %s: unsupported PEM type %q", path, block.Type)
	}
}
