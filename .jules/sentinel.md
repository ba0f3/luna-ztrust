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

## 2024-05-31 - [Prevent Information Exposure in CLI Error Handling]
**Vulnerability:** The HTTP client for CLI key load blindly appended the raw external API response body (`j.Error` and `j.Code` from unmarshaled JSON) to `fmt.Errorf` strings. This could expose sensitive identifiers, paths, or internal server state in application logs or CLI output.
**Learning:** Always avoid blindly appending external API or HTTP response data to error strings. Even parsed sub-fields like `error` or `code` can leak internal details if the remote server is misconfigured or returning unexpected data.
**Prevention:** Log or return just the HTTP status code or safe, predefined error constants instead of raw or parsed response strings.
## 2026-08-25 - Avoid Unbounded HTTP Request Readings in Tests
**Vulnerability:** HTTP API response bodies (and request bodies in mock servers) were being read using `io.ReadAll(resp.Body)` and `json.NewDecoder(resp.Body)` without a size limit in test files.
**Learning:** While test files aren't directly part of the production service, running tests on large datasets or compromised servers could theoretically exhaust memory. Keeping test environments aligned with production mitigations promotes standard coding practices across the entire codebase.
**Prevention:** Consistently use `io.LimitReader` when reading HTTP response bodies (e.g., `io.ReadAll(io.LimitReader(resp.Body, 1<<20))`) or `json.NewDecoder(io.LimitReader(resp.Body, 1<<20))` across tests.
## 2026-06-26 - Safely Drain HTTP Response Bodies
**Vulnerability:** HTTP response bodies in clients (e.g., `Notify` in Telegram approval) were being closed without being read, which can cause connection leaks in Go.
**Learning:** In Go, failing to drain an HTTP response body before closing it prevents the underlying TCP connection from being reused by `http.Transport`, leading to resource exhaustion (DoS) under load.
**Prevention:** Always safely drain the response body to prevent connection leaks using `io.Copy(io.Discard, io.LimitReader(resp.Body, maxBytes))` before calling `resp.Body.Close()`, even if the body content is not needed.
## 2026-09-12 - Avoid Information Exposure in Error Handling
**Vulnerability:** The HTTP clients for Telegram APIs blindly wrapped `json.Unmarshal` errors containing remote API fragments with `fmt.Errorf`.
**Learning:** Even `json.Unmarshal` error messages can contain text fragments from raw external API responses if there is a parsing error, which might leak internal details if the remote server returns unexpected data.
**Prevention:** Log or return just the HTTP status code or safe, predefined error constants instead of raw or parsed response strings, avoiding error wrapping for unmarshaling HTTP responses.
## 2026-10-18 - Avoid Information Exposure from json.Unmarshal Errors
**Vulnerability:** In Telegram HTTP clients (and others), `json.Unmarshal` errors were directly included in `fmt.Errorf` without masking the original error (`%w` or `%v`).
**Learning:** Unmarshal errors on external API endpoints can expose raw fragments of unexpected HTTP responses. It is critical to sanitize the error to avoid leaking internal variables or state via logs.
**Prevention:** Remove `%w` and only format safe static strings or HTTP status code, for example: `fmt.Errorf("telegram %s: invalid json response", method)` instead of `fmt.Errorf("...: %w", err)`.
