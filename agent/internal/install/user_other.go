//go:build !linux

package install

import "fmt"

func EnsureServiceUser(username, group string) error {
	return fmt.Errorf("install systemd user setup requires Linux")
}

func EnsureLunaDirs(username, group string) error {
	return nil
}

func EnsureCertPermissions(dir, group string) error {
	return nil
}
