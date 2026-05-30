package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/control/client"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Query proxy seal and signer status",
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(_ *cobra.Command, _ []string) error {
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	data, err := client.Call(path, "status", nil)
	if err != nil {
		return err
	}
	var pretty interface{}
	if err := json.Unmarshal(data, &pretty); err != nil {
		_, _ = fmt.Fprintln(os.Stdout, string(data))
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(pretty)
}

func resolveSocket() (string, error) {
	if socketPath != "" {
		return socketPath, nil
	}
	cfg, err := config.Load()
	if err != nil {
		return "", err
	}
	if cfg.ControlSocket != "" {
		return cfg.ControlSocket, nil
	}
	return "/run/luna/control.sock", nil
}
