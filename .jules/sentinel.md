## 2026-06-02 - Missing Input Length Limits
**Vulnerability:** The HTTP API endpoints in `proxy/internal/api/mobile_handler.go` (`handleMobileEnroll` and `handleMobileApprove`) read unbounded JSON request bodies.
**Learning:** Endpoints processing user input directly using `json.NewDecoder(r.Body)` are exposed to large payload DoS attacks if `http.MaxBytesReader` is not applied.
**Prevention:** Use `http.MaxBytesReader(w, r.Body, maxBodySize)` before decoding JSON on all HTTP handlers handling user input.
