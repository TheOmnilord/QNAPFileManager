Existing tests and the three-target vet sweep pass, but focused probes reproduce ineffective authentication throttling and incorrect Windows drive-root jail resolution.

Full review comments:

- [P2] Enforce failure throttling before issuing more CGI calls — C:\Dev\QNAPFileManager\internal\web\auth_limits.go:83-88
  When a client repeatedly supplies distinct invalid tokens, every request reaches QTS before the failure limiter runs. A probe sent 100 requests from one IP and observed 100 CGI calls, despite 80 responses being HTTP 429. Changing tokens bypasses the negative cache, allowing an unauthenticated client to continuously consume validation capacity. Bound upstream work from abusive sources before verification, while retaining bounded recovery admission for legitimate clients.

- [P2] Preserve the separator on Windows drive roots — C:\Dev\QNAPFileManager\internal\fsx\root.go:82-85
  On Windows, supplying `-jail C:\` trims the base to `C:`, which denotes the drive's current directory rather than its root. A probe from this workspace consequently listed the repository instead of the drive root. Preserve drive-root separators and adjust the containment/path conversion logic accordingly so filesystem requests address the configured jail.
