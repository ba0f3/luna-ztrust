package control

import "testing"

func TestZeroString(t *testing.T) {
	s := "secret-pass"
	ZeroString(&s)
	if s != "" {
		t.Fatalf("string not cleared")
	}
}
