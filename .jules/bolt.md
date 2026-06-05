## 2024-06-03 - Base64 Encoding Optimization
**Learning:** Using `base64.StdEncoding` and manual string manipulation (`strings.TrimRight(s, "=")` and string padding) for OpenSSH SHA256 fingerprints introduces unnecessary memory allocations.
**Action:** Use `base64.RawStdEncoding` directly when encoding/decoding unpadded base64 strings (like OpenSSH fingerprints) to avoid manual string allocations and improve performance.
## 2026-06-03 - Base64 Encoding Trimming Fallacy
**Learning:** In Go, `strings.TrimRight` returns a sub-slice of the original string and does not allocate new memory. Therefore, optimizing out `strings.TrimRight(s, "=")` on existing strings based on the assumption that it "saves an allocation" is incorrect and can lead to regressions if padding variations exist.
**Action:** Do not remove `strings.TrimRight` from normalization functions for performance reasons. Only optimize base64 generation by using `RawStdEncoding` directly to avoid creating the padding in the first place.
## 2026-06-05 - Avoid fmt.Sprintf in hot paths for byte arrays
**Learning:** In Go, converting strings to byte arrays via `fmt.Sprintf("%s:%s:%d", ...)` causes multiple heap allocations and memory overhead, heavily impacting the hot path, especially within high-traffic functions like cryptographic challenge generation or PoP signing.
**Action:** Use manual byte slice construction with pre-calculated sizing and `strconv.AppendInt` for numeric types to avoid allocations and substantially improve throughput and reduce memory overhead.
