package cli

import "errors"

const MaxLabelLen = 128

var ErrLabelTooLong = errors.New("device label too long")

// ValidateLabel checks operator-visible device labels.
func ValidateLabel(label string) error {
	if label == "" {
		return ErrEmptyLabel
	}
	if len(label) > MaxLabelLen {
		return ErrLabelTooLong
	}
	return nil
}
