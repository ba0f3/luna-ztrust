package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

type signerRow struct {
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
}

func formatSHA256(fingerprint string) string {
	if fingerprint == "" {
		return "SHA256:"
	}
	return "SHA256:" + fingerprint
}

func writeFingerprintLine(w io.Writer, prefix, fingerprint, comment string) {
	if comment != "" {
		fmt.Fprintf(w, "%s%s  %s\n", prefix, formatSHA256(fingerprint), comment)
		return
	}
	fmt.Fprintf(w, "%s%s\n", prefix, formatSHA256(fingerprint))
}

func writeSigners(w io.Writer, prefix string, signers []signerRow) {
	if len(signers) == 0 {
		fmt.Fprintf(w, "%s(none)\n", prefix)
		return
	}
	sort.Slice(signers, func(i, j int) bool {
		return signers[i].Fingerprint < signers[j].Fingerprint
	})
	for _, s := range signers {
		writeFingerprintLine(w, prefix, s.Fingerprint, s.Comment)
	}
}

func formatKeyLoadResult(data json.RawMessage) (string, error) {
	var out struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	return formatSHA256(out.Fingerprint) + "\n", nil
}

func printKeyLoadResult(data json.RawMessage) error {
	line, err := formatKeyLoadResult(data)
	if err != nil {
		return err
	}
	_, err = os.Stdout.WriteString(line)
	return err
}

func formatKeyListResult(data json.RawMessage) (string, error) {
	var out struct {
		Signers []signerRow `json:"signers"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	writeSigners(&buf, "", out.Signers)
	return buf.String(), nil
}

func printKeyListResult(data json.RawMessage) error {
	out, err := formatKeyListResult(data)
	if err != nil {
		return err
	}
	_, err = os.Stdout.WriteString(out)
	return err
}

func formatStatusResult(data json.RawMessage) (string, error) {
	var out struct {
		Sealed     bool        `json:"sealed"`
		SignerMode string      `json:"signer_mode"`
		Loaded     []signerRow `json:"loaded"`
		Pending    int         `json:"pending"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "sealed: %t\n", out.Sealed)
	fmt.Fprintf(&buf, "signer_mode: %s\n", out.SignerMode)
	fmt.Fprintln(&buf, "loaded:")
	writeSigners(&buf, "  ", out.Loaded)
	fmt.Fprintf(&buf, "pending: %d\n", out.Pending)
	return buf.String(), nil
}

func printStatusResult(data json.RawMessage) error {
	out, err := formatStatusResult(data)
	if err != nil {
		return err
	}
	_, err = os.Stdout.WriteString(out)
	return err
}

type cliDeviceRow struct {
	DeviceID        string `json:"device_id"`
	Label           string `json:"label"`
	CertFingerprint string `json:"cert_fingerprint"`
	EnrolledAt      string `json:"enrolled_at"`
}

func formatCLIListResult(data json.RawMessage) (string, error) {
	var out struct {
		Devices []cliDeviceRow `json:"devices"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if len(out.Devices) == 0 {
		fmt.Fprintln(&buf, "(none)")
		return buf.String(), nil
	}
	sort.Slice(out.Devices, func(i, j int) bool {
		return out.Devices[i].DeviceID < out.Devices[j].DeviceID
	})
	for _, d := range out.Devices {
		fmt.Fprintf(&buf, "%s  %s  %s  %s\n", d.DeviceID, d.Label, d.CertFingerprint, d.EnrolledAt)
	}
	return buf.String(), nil
}

func printCLIListResult(data json.RawMessage) error {
	out, err := formatCLIListResult(data)
	if err != nil {
		return err
	}
	_, err = os.Stdout.WriteString(out)
	return err
}
