## 2026-06-02 - Missing Input Length Limits
**Vulnerability:** The HTTP API endpoints in `proxy/internal/api/mobile_handler.go` (`handleMobileEnroll` and `handleMobileApprove`) read unbounded JSON request bodies.
**Learning:** Endpoints processing user input directly using `json.NewDecoder(r.Body)` are exposed to large payload DoS attacks if `http.MaxBytesReader` is not applied.
**Prevention:** Use `http.MaxBytesReader(w, r.Body, maxBodySize)` before decoding JSON on all HTTP handlers handling user input.
## 2026-06-11 - Exposed sensitive data in logs or error messages
**Vulnerability:** Telegram raw HTTP response bodies were being appended to fmt.Errorf calls.
**Learning:** Including raw external API responses in formatted error strings risks exposing sensitive internal identifiers, tokens, or network infrastructure details in application logs.
**Prevention:** Avoid blindly appending body responses to errors; instead, log just the HTTP status code or safe/parsed sub-fields.
## 2026-06-23 - Exposed sensitive data in error messages
**Vulnerability:** HTTP API response bodies were being appended blindly to fmt.Errorf calls in client functions.
**Learning:** Including raw external API responses in formatted error strings risks exposing sensitive internal identifiers, tokens, or network infrastructure details in application logs.
**Prevention:** Avoid blindly appending body responses to errors; instead, log just the HTTP status code or safe/parsed sub-fields.
## 2025-02-09 - Avoid Logging Raw External API Bodies
**Vulnerability:** Raw HTTP response bodies from external or untrusted APIs were being blindly appended to `fmt.Errorf` and potentially exposed in application logs or CLI outputs. This can leak sensitive internal tokens or identifiers if the API proxy/server returns unexpected data.
**Learning:** Found multiple instances where API clients (`sdk/sign/client.go`, `proxy/internal/cli/httpclient/enroll.go`, `load.go`) would embed the entire response body in the error if parsing failed.
**Prevention:** Drain HTTP response bodies but do not append them raw to errors. Log or return only the HTTP status code, or parse structured data explicitly before emitting any values.
## 2026-06-25 - Avoid Unbounded io.ReadAll on HTTP Responses
**Vulnerability:** HTTP API response bodies were being read using `io.ReadAll(resp.Body)` without a size limit.
**Learning:** Reading HTTP response bodies without bounds allows a malicious or compromised server to send excessively large payloads, leading to memory exhaustion and potentially crashing the application (Denial of Service).
**Prevention:** Always use `io.LimitReader` when reading HTTP response bodies (e.g., `io.ReadAll(io.LimitReader(resp.Body, 1<<20))`) to enforce a safe maximum memory allocation.
