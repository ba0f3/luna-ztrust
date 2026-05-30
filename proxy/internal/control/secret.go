package control

// ZeroBytes overwrites b before release. Safe for passphrase copies.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroString best-effort clears a passphrase string by copying to a mutable buffer.
func ZeroString(s *string) {
	if s == nil || *s == "" {
		return
	}
	b := []byte(*s)
	ZeroBytes(b)
	*s = ""
}
