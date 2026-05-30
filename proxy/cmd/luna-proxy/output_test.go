package main

import (
	"encoding/json"
	"testing"
)

func TestFormatSHA256(t *testing.T) {
	got := formatSHA256("abc123")
	want := "SHA256:abc123"
	if got != want {
		t.Fatalf("formatSHA256() = %q, want %q", got, want)
	}
}

func TestFormatKeyListResult(t *testing.T) {
	data := json.RawMessage(`{"signers":[{"fingerprint":"bbb","comment":"host-b"},{"fingerprint":"aaa"}]}`)
	out, err := formatKeyListResult(data)
	if err != nil {
		t.Fatal(err)
	}
	want := "SHA256:aaa\nSHA256:bbb  host-b\n"
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestFormatStatusResult(t *testing.T) {
	data := json.RawMessage(`{"sealed":false,"signer_mode":"local-key","loaded":[{"fingerprint":"deadbeef","comment":"ca"}],"pending":0}`)
	out, err := formatStatusResult(data)
	if err != nil {
		t.Fatal(err)
	}
	want := "sealed: false\nsigner_mode: local-key\nloaded:\n  SHA256:deadbeef  ca\npending: 0\n"
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestFormatKeyLoadResult(t *testing.T) {
	data := json.RawMessage(`{"fingerprint":"ErTRveOaqaSJSj9pi4mTOQdskJUmTE45h2AFw2qmIYw"}`)
	out, err := formatKeyLoadResult(data)
	if err != nil {
		t.Fatal(err)
	}
	if out != "SHA256:ErTRveOaqaSJSj9pi4mTOQdskJUmTE45h2AFw2qmIYw\n" {
		t.Fatalf("output = %q", out)
	}
}
