package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ba0f3/luna-ztrust/proxy/internal/control/client"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var passphraseStdin bool

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
	keyConfirmCmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "read passphrase from stdin")
	keyCmd.AddCommand(keyLoadCmd, keyListCmd, keyRemoveCmd, keyConfirmCmd, keyRejectCmd)
	rootCmd.AddCommand(keyCmd)
}

func runKeyLoad(_ *cobra.Command, args []string) error {
	pass, err := readPassphrase()
	if err != nil {
		return err
	}
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	data, err := client.Call(path, "key.load", map[string]string{
		"path":       args[0],
		"passphrase": pass,
	})
	if err != nil {
		return err
	}
	return printKeyLoadResult(data)
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
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	data, err := client.Call(path, "key.confirm", map[string]string{
		"pending_id": args[0],
		"passphrase": pass,
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

func readPassphrase() (string, error) {
	if passphraseStdin {
		sc := bufio.NewScanner(os.Stdin)
		if sc.Scan() {
			return strings.TrimSpace(sc.Text()), nil
		}
		return "", sc.Err()
	}
	fmt.Fprint(os.Stderr, "Passphrase: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(pass), nil
	}
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text()), nil
	}
	return "", sc.Err()
}
