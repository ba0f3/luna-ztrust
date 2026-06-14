## 2024-06-03 - Base64 Encoding Optimization
**Learning:** Using `base64.StdEncoding` and manual string manipulation (`strings.TrimRight(s, "=")` and string padding) for OpenSSH SHA256 fingerprints introduces unnecessary memory allocations.
**Action:** Use `base64.RawStdEncoding` directly when encoding/decoding unpadded base64 strings (like OpenSSH fingerprints) to avoid manual string allocations and improve performance.
## 2026-06-03 - Base64 Encoding Trimming Fallacy
**Learning:** In Go, `strings.TrimRight` returns a sub-slice of the original string and does not allocate new memory. Therefore, optimizing out `strings.TrimRight(s, "=")` on existing strings based on the assumption that it "saves an allocation" is incorrect and can lead to regressions if padding variations exist.
**Action:** Do not remove `strings.TrimRight` from normalization functions for performance reasons. Only optimize base64 generation by using `RawStdEncoding` directly to avoid creating the padding in the first place.
## 2026-06-05 - Avoid fmt.Sprintf in hot paths for byte arrays
**Learning:** In Go, converting strings to byte arrays via `fmt.Sprintf("%s:%s:%d", ...)` causes multiple heap allocations and memory overhead, heavily impacting the hot path, especially within high-traffic functions like cryptographic challenge generation or PoP signing.
**Action:** Use manual byte slice construction with pre-calculated sizing and `strconv.AppendInt` for numeric types to avoid allocations and substantially improve throughput and reduce memory overhead.
## 2026-06-09 - Avoid pointer indirection in loop accumulations
**Learning:** Using a pointer to track the "best" or "latest" struct within a loop (e.g., `cp := l; best = &cp`) often causes the local copy to escape to the heap in Go, leading to unnecessary memory allocations on hot paths.
**Action:** Use value semantics and a separate boolean flag (e.g., `var best Struct`, `found := false`) to accumulate state in loops. This allows the compiler to keep the accumulator on the stack or in registers, eliminating heap allocations and GC pressure.
## 2026-06-11 - Use Struct Keys in Maps to Avoid Allocations
**Learning:** In Go, structs containing comparable types (like strings) can be used directly as map keys. Serializing structs into strings with custom delimiters (`strings.Join`, etc.) to use as map keys forces memory allocations on every lookup, degrading performance on hot paths like authentication or lease checking.
**Action:** Use struct values as map keys directly instead of stringifying them. This allows the Go runtime to hash the struct fields efficiently without any heap allocations.
## 2026-06-14 - Map Key String Allocation Optimization
**Learning:** Using `string(b)` to convert a byte slice (`[]byte`) to a string for use as a map key introduces a heap allocation per lookup/insertion. On hot paths, this causes significant GC pressure and slows down operations like replay caches.
**Action:** Use fixed-size byte arrays (e.g. `[32]byte`) directly as map keys where applicable (like when working with SHA-256 hashes) to eliminate the casting allocations completely and improve cache throughput.
