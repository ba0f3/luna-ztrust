package main

import (
	"fmt"

	"github.com/ba0f3/luna-ztrust/agent/internal/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print binary version",
	Run: func(*cobra.Command, []string) {
		fmt.Print(version.Full("luna-agent"))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.Version = version.String()
	rootCmd.SetVersionTemplate("{{.Version}}\n")
}
