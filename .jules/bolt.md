## 2024-06-03 - Base64 Encoding Optimization
**Learning:** Using `base64.StdEncoding` and manual string manipulation (`strings.TrimRight(s, "=")` and string padding) for OpenSSH SHA256 fingerprints introduces unnecessary memory allocations.
**Action:** Use `base64.RawStdEncoding` directly when encoding/decoding unpadded base64 strings (like OpenSSH fingerprints) to avoid manual string allocations and improve performance.
