## 2026-06-02 - Missing Input Length Limits
**Vulnerability:** The HTTP API endpoints in `proxy/internal/api/mobile_handler.go` (`handleMobileEnroll` and `handleMobileApprove`) read unbounded JSON request bodies.
**Learning:** Endpoints processing user input directly using `json.NewDecoder(r.Body)` are exposed to large payload DoS attacks if `http.MaxBytesReader` is not applied.
**Prevention:** Use `http.MaxBytesReader(w, r.Body, maxBodySize)` before decoding JSON on all HTTP handlers handling user input.
## 2026-06-11 - Exposed sensitive data in logs or error messages
**Vulnerability:** Telegram raw HTTP response bodies were being appended to fmt.Errorf calls.
**Learning:** Including raw external API responses in formatted error strings risks exposing sensitive internal identifiers, tokens, or network infrastructure details in application logs.
**Prevention:** Avoid blindly appending body responses to errors; instead, log just the HTTP status code or safe/parsed sub-fields.
