package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var socketPath string

var rootCmd = &cobra.Command{
	Use:   "luna-proxy",
	Short: "Luna Z-Trust central proxy",
	Long:  "Self-hosted SSH signing gateway with mTLS API and local control socket.",
	RunE: func(cmd *cobra.Command, _ []string) error {
		return cmd.Help()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "", "Unix control socket (default from config or /run/luna/control.sock)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
