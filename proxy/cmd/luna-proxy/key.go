package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/ba0f3/luna-ztrust/proxy/internal/cli/httpclient"
	"github.com/ba0f3/luna-ztrust/proxy/internal/control"
	"github.com/ba0f3/luna-ztrust/proxy/internal/control/client"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	passphraseStdin bool
	keyLoadProxyURL string
	keyLoadCliCert  string
	keyLoadCliKey   string
	keyLoadCA       string
	keyLoadLabel    string
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage signing keys in the proxy keystore",
}

var keyLoadCmd = &cobra.Command{
	Use:   "load [path]",
	Short: "Load an encrypted PEM signing key",
	Args:  cobra.ExactArgs(1),
	RunE:  runKeyLoad,
}

var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List loaded signing keys",
	RunE:  runKeyList,
}

var keyRemoveCmd = &cobra.Command{
	Use:   "remove [fingerprint]",
	Short: "Remove a loaded signing key",
	Args:  cobra.ExactArgs(1),
	RunE:  runKeyRemove,
}

var keyConfirmCmd = &cobra.Command{
	Use:   "confirm [pending-id]",
	Short: "Confirm a mobile-uploaded pending key",
	Args:  cobra.ExactArgs(1),
	RunE:  runKeyConfirm,
}

var keyRejectCmd = &cobra.Command{
	Use:   "reject [pending-id]",
	Short: "Reject a pending key upload",
	Args:  cobra.ExactArgs(1),
	RunE:  runKeyReject,
}

func init() {
	keyLoadCmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "read passphrase from stdin")
	keyLoadCmd.Flags().StringVar(&keyLoadProxyURL, "proxy-url", "", "proxy HTTPS base URL for remote key load")
	keyLoadCmd.Flags().StringVar(&keyLoadCliCert, "cli-cert", "", "enrolled CLI client certificate (mTLS)")
	keyLoadCmd.Flags().StringVar(&keyLoadCliKey, "cli-key", "", "CLI client private key (mTLS)")
	keyLoadCmd.Flags().StringVar(&keyLoadCA, "ca", "", "mTLS CA certificate (optional; downloaded from GET /api/v1/mtls/ca)")
	keyLoadCmd.Flags().StringVar(&keyLoadLabel, "label", "", "signer label (required for remote key load)")
	keyConfirmCmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "read passphrase from stdin")
	keyCmd.AddCommand(keyLoadCmd, keyListCmd, keyRemoveCmd, keyConfirmCmd, keyRejectCmd)
	rootCmd.AddCommand(keyCmd)
}

func runKeyLoad(cmd *cobra.Command, args []string) error {
	pass, err := readPassphrase()
	if err != nil {
		return err
	}
	defer control.ZeroBytes(pass)

	prof, err := resolveCLIProfile(cmd)
	if err != nil {
		return err
	}
	if prof != nil {
		ctx := context.Background()
		if err := prof.validateKeyLoad(); err != nil {
			return err
		}
		if err := prof.ensureProfileCA(ctx); err != nil {
			return fmt.Errorf("fetch CA: %w", err)
		}
		label := keyLoadLabel
		if label == "" {
			return fmt.Errorf("--label is required for remote key load")
		}
		fp, err := httpclient.Load(ctx, httpclient.Config{
			ProxyURL: prof.ProxyURL,
			CliCert:  prof.CliCert,
			CliKey:   prof.CliKey,
			CA:       prof.CA,
		}, args[0], pass, label)
		if err != nil {
			return err
		}
		data, err := json.Marshal(map[string]string{"fingerprint": fp})
		if err != nil {
			return err
		}
		return printKeyLoadResult(data)
	}

	path, err := resolveSocket()
	if err != nil {
		return fmt.Errorf("configure %s or use --socket for on-host key load: %w", cliProfilePath(), err)
	}
	data, err := client.Call(path, "key.load", map[string]string{
		"path":       args[0],
		"passphrase": string(pass),
	})
	if err != nil {
		if isSocketUnavailable(err) {
			return fmt.Errorf("configure %s for remote key load or run on the central host with control socket access", cliProfilePath())
		}
		return err
	}
	return printKeyLoadResult(data)
}

func isSocketUnavailable(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

func runKeyList(_ *cobra.Command, _ []string) error {
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	data, err := client.Call(path, "key.list", nil)
	if err != nil {
		return err
	}
	return printKeyListResult(data)
}

func runKeyRemove(_ *cobra.Command, args []string) error {
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	_, err = client.Call(path, "key.remove", map[string]string{"fingerprint": args[0]})
	return err
}

func runKeyConfirm(_ *cobra.Command, args []string) error {
	pass, err := readPassphrase()
	if err != nil {
		return err
	}
	defer control.ZeroBytes(pass)
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	data, err := client.Call(path, "key.confirm", map[string]string{
		"pending_id": args[0],
		"passphrase": string(pass),
	})
	if err != nil {
		return err
	}
	return printKeyLoadResult(data)
}

func runKeyReject(_ *cobra.Command, args []string) error {
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	_, err = client.Call(path, "key.reject", map[string]string{"pending_id": args[0]})
	return err
}

func readPassphrase() ([]byte, error) {
	if passphraseStdin {
		sc := bufio.NewScanner(os.Stdin)
		if sc.Scan() {
			return bytes.TrimSpace(sc.Bytes()), nil
		}
		return nil, sc.Err()
	}
	fmt.Fprint(os.Stderr, "Passphrase: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		return pass, nil
	}
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		return bytes.TrimSpace(sc.Bytes()), nil
	}
	return nil, sc.Err()
}
