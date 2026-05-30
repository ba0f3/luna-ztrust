package main

import (
	"fmt"

	"github.com/ba0f3/luna-ztrust/proxy/internal/control/client"
	"github.com/spf13/cobra"
)

var (
	mobileLabel  string
	mobilePubKey string
)

var mobileCmd = &cobra.Command{
	Use:   "mobile",
	Short: "Manage enrolled mobile devices",
}

var mobileEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll a mobile device",
	RunE:  runMobileEnroll,
}

var mobileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List enrolled mobile devices",
	RunE:  runMobileList,
}

var mobileDeleteCmd = &cobra.Command{
	Use:   "delete [device-id]",
	Short: "Delete an enrolled device",
	Args:  cobra.ExactArgs(1),
	RunE:  runMobileDelete,
}

func init() {
	mobileEnrollCmd.Flags().StringVar(&mobileLabel, "label", "", "device label")
	mobileEnrollCmd.Flags().StringVar(&mobilePubKey, "pubkey", "", "base64 device public key")
	_ = mobileEnrollCmd.MarkFlagRequired("label")
	_ = mobileEnrollCmd.MarkFlagRequired("pubkey")
	mobileCmd.AddCommand(mobileEnrollCmd, mobileListCmd, mobileDeleteCmd)
	rootCmd.AddCommand(mobileCmd)
}

func runMobileEnroll(_ *cobra.Command, _ []string) error {
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	data, err := client.Call(path, "mobile.enroll", map[string]string{
		"label":         mobileLabel,
		"device_pubkey": mobilePubKey,
	})
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func runMobileList(_ *cobra.Command, _ []string) error {
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	data, err := client.Call(path, "mobile.list", nil)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func runMobileDelete(_ *cobra.Command, args []string) error {
	path, err := resolveSocket()
	if err != nil {
		return err
	}
	_, err = client.Call(path, "mobile.delete", map[string]string{"device_id": args[0]})
	return err
}
