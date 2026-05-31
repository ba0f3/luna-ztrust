package cli

import (
	"errors"
	"testing"
)

func TestValidateLabel(t *testing.T) {
	if err := ValidateLabel("laptop"); err != nil {
		t.Fatalf("valid label: %v", err)
	}
	if err := ValidateLabel(""); !errors.Is(err, ErrEmptyLabel) {
		t.Fatalf("empty: %v", err)
	}
	long := make([]byte, MaxLabelLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if err := ValidateLabel(string(long)); !errors.Is(err, ErrLabelTooLong) {
		t.Fatalf("long label: %v", err)
	}
}
