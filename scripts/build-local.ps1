# Cross-compiles the qnapfilemanager binary for both QNAP architectures.
# The full QPKG is built by GitHub Actions; this is for copying a binary onto
# the NAS by hand between releases.
param([string]$Version = "0.0.0-local")

# The env vars are process-wide; clean them up on every exit path, or one
# failed build leaves the calling shell silently cross-compiling linux
# binaries for the rest of the session.
try {
    # CGO_ENABLED=0 is what makes the binary run on QTS's bare userland.
    $env:CGO_ENABLED = "0"
    $env:GOOS = "linux"
    foreach ($arch in "amd64", "arm64") {
        $env:GOARCH = $arch
        go build -trimpath -ldflags "-s -w -X main.version=$Version" -o "dist/$arch/bin/qnapfilemanager" ./cmd/qnapfilemanager
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Write-Host "built dist/$arch/bin/qnapfilemanager"
    }
} finally {
    Remove-Item env:GOOS, env:GOARCH, env:CGO_ENABLED -ErrorAction SilentlyContinue
}
