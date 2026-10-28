1. **Fix information exposure in `proxy/internal/keystore/resolve.go`**
   - In `ResolveHostKeyFingerprint`, modify the `fmt.Errorf("decode host_public_key: %w", err)` to avoid `%w` and prevent exposing potential sensitive information or raw error messages directly. Change it to `fmt.Errorf("decode host_public_key: invalid base64")`.
   - Also, modify `fmt.Errorf("parse host_public_key: %w", err)` to avoid `%w`. Change it to `fmt.Errorf("parse host_public_key: invalid format")`.
2. **Fix information exposure in `sdk/sign/signature.go`**
   - In `RequestSignature`, modify `fmt.Errorf("decode ssh_signature: %w", err)` to remove `%w`. Change it to `fmt.Errorf("decode ssh_signature: invalid base64")`.
3. **Run the test suite**
   - Ensure the mTLS test materials are generated using `make testdata`.
   - Ensure the test suite passes with `make test`.
4. **Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.**
   - Run `pre_commit_instructions` tool.
5. **Create a Pull Request**
   - Submit the PR with the title: `🛡️ Sentinel: [MEDIUM] Fix Information Exposure from base64 decode and parse Errors`
   - Include required PR description bullet points for the Sentinel persona:
     * 🚨 Severity: MEDIUM
     * 💡 Vulnerability: Information exposure from base64 decode and parse errors.
     * 🎯 Impact: Raw fragment of external strings or untrusted payload might be leaked into logs or error messages.
     * 🔧 Fix: Replaced `%w` with safe static error strings in `fmt.Errorf`.
     * ✅ Verification: Verified test passes correctly and the codebase follows security standards.
