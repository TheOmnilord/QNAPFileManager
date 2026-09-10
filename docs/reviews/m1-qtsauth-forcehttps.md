**Loopback pinning is sound.** [internal/qtsauth/client.go:367](C:/Dev/QNAPFileManager/internal/qtsauth/client.go:367) constructs the fallback using literal `https://127.0.0.1:` plus a validated integer. The redirect’s hostname, userinfo, path, and query are discarded. The fallback transport disables proxies and redirect following. No redirect syntax can make that transport connect directly to another host.

Three confident findings:

1. **The redirect can select an arbitrary loopback authentication service.** [internal/qtsauth/client.go:323](C:/Dev/QNAPFileManager/internal/qtsauth/client.go:323), [client.go:381](C:/Dev/QNAPFileManager/internal/qtsauth/client.go:381).

   A compromised HTTP endpoint can return `Location: https://anything:9443/`. If an attacker controls a TLS listener on local port 9443, it receives the original credentials and can return `<authPassed>1</authPassed><isAdmin>1</isAdmin><username>admin</username>`. An admin-claimed qtoken or matching SID identity then passes verification. Any certificate suffices.

   This is a real expansion of trusted endpoints, although a fully compromised QTS authentication server could already forge the original response. It is not an independently exploitable remote-host redirect.

   **Minimal fix:** use only the configured SSL port, or require the redirect port to match it. The existing 8770 listener serves plain HTTP, so the TLS handshake fails before XML parsing; I found no demonstrated forged-auth route through 8771.

2. **Stripping the outer `url.Error` does not guarantee token-free errors.** [internal/qtsauth/client.go:305](C:/Dev/QNAPFileManager/internal/qtsauth/client.go:305).

   A fallback HTTPS endpoint can return a 302 with malformed `Location: https://nas:bad/?sid=SECRET`, reflecting the received token. Go parses `Location` before invoking `CheckRedirect`; its underlying error contains the entire malformed header. Assigning `err = ue.Err` preserves that secret, and line 311 returns it.

   `redactQuery` protects the explicitly formatted query, but does not sanitize the underlying error. This weakness predates the commit and remains reachable on the new HTTPS path. An HTTP-primary error is normally superseded by the fallback result. I found no current web-handler logging of this returned error, so the confirmed exposure is in the error value.

   **Minimal fix:** return a sanitized error classification and `ErrUnreachable`, without embedding arbitrary transport-error text; retain cancellation/timeout classification explicitly.

3. **An HTTP-port override discards the detected SSL port.** [cmd/qnapfilemanager/main.go:317](C:/Dev/QNAPFileManager/cmd/qnapfilemanager/main.go:317).

   With `cfg.Auth.QTSPort` set, the detected client is replaced with `New(...)`, losing `SSLPort`. On a unit with HTTP disabled and stunnel on a nonstandard port, fallback incorrectly attempts 443 and authentication fails.

   **Minimal fix:** update the detected client’s HTTP base/client while retaining its `SSLPort`, or copy that field into the replacement.

Other requested checks:

- **Redirect edge cases:** [client.go:322](C:/Dev/QNAPFileManager/internal/qtsauth/client.go:322) retries for **every 3xx**, including HTTP redirects and missing `Location`. Zero/out-of-range ports select configured SSL, then 443. Nonnumeric ports can fail inside Go’s redirect parser and reach the same configured fallback through the error branch. HTTPS without an explicit port selects 443. These remain loopback-bound, but contradict the “redirected to HTTPS” condition. To enforce that condition, distinguish an invalid/non-HTTPS location from an HTTPS redirect needing a default port.
- **No loop:** [client.go:285](C:/Dev/QNAPFileManager/internal/qtsauth/client.go:285) performs one explicit retry; HTTPS cannot produce another fallback. There is no recursion.
- **TLS:** ordinary remote network attackers cannot intercept this loopback connection. Privileged local traffic interception or endpoint replacement remains possible; `InsecureSkipVerify` supplies no protection against those attackers.
- **Fail-closed/cache/timeouts:** SID binding and admin checks remain intact at [verifier.go:358](C:/Dev/QNAPFileManager/internal/qtsauth/verifier.go:358) and [verifier.go:399](C:/Dev/QNAPFileManager/internal/qtsauth/verifier.go:399). Both attempts share one flight and validation slot; only the final result is cached. Cancellation prevents caching. Each attempt has its own timeout, allowing approximately ten seconds combined; the web layer already imposes a ten-second authentication deadline and invalidates infrastructure-error cache entries.

Read-only inspection completed; no files modified or tests run.