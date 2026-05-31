package control

// ZeroBytes overwrites b before release. Safe for passphrase copies.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
