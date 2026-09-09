# Builds testdata\fakeroot: a small, realistic QTS filesystem for the Windows
# dev loop, so `serve -jail testdata\fakeroot` behaves like a NAS.
#
# Everything here mirrors something the real thing has and something the code
# has to survive: /etc/passwd and /etc/group for idmap, /etc/config for the
# guard's protected-path table, the two shapes of entry that live side by side
# at /share, a name with a space and a '#' in it (which has to survive URL
# encoding), and a unicode name.
#
# Regenerate it whenever it looks wrong; it is gitignored and disposable.
param(
    [string]$Path = (Join-Path (Split-Path -Parent $PSScriptRoot) "testdata\fakeroot"),
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if (Test-Path $Path) {
    if (-not $Force) {
        Write-Host "$Path already exists; pass -Force to rebuild it."
        exit 0
    }
    Remove-Item -Recurse -Force $Path
}

function New-Dir([string]$p) { New-Item -ItemType Directory -Force -Path $p | Out-Null }

# Written without a BOM and with LF endings: these stand in for Linux system
# files, and a parser that trips over a CR here would pass on the NAS and fail
# nowhere else.
function Set-LinuxFile([string]$p, [string]$content) {
    New-Dir (Split-Path -Parent $p)
    $lf = $content -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($p, $lf, (New-Object System.Text.UTF8Encoding($false)))
}

New-Dir $Path
$root = (Resolve-Path $Path).Path

Set-LinuxFile "$root\etc\passwd" @"
admin:x:0:0:administrator:/share/homes/admin:/bin/sh
root:x:0:0:root:/root:/bin/sh
guest:x:65534:65534:guest:/tmp:/bin/sh
httpdusr:x:99:99:httpdusr:/tmp:/bin/sh
sveinung:x:1000:100:Sveinung:/share/homes/sveinung:/bin/sh
kari:x:1001:100:Kari:/share/homes/kari:/bin/sh
"@

Set-LinuxFile "$root\etc\group" @"
administrators:x:0:admin
everyone:x:100:sveinung,kari
users:x:100:
guest:x:65534:
media:x:1002:sveinung
"@

# The firmware configuration the guard protects, and the file the QTS web port
# is read from.
Set-LinuxFile "$root\etc\config\uLinux.conf" @"
[System]
Model = TS-464
Version = 5.2.0
Number = 20250101

[Web]
Enable = TRUE
Web Access Port = 8080
Web Access SSL Port = 443
Force SSL = FALSE
"@

Set-LinuxFile "$root\etc\config\qpkg.conf" @"
[QNAPFileManager]
Name = QNAPFileManager
Version = 0.1.0
Enable = TRUE
Install_Path = /share/CACHEDEV1_DATA/.qpkg/QNAPFileManager
Web_Port = 8770
Proxy_Path = /qnapfilemanager
"@

# '/etc/configuration' exists only to catch a prefix test that is not path
# boundary aware: it must NOT be treated as being inside '/etc/config'.
Set-LinuxFile "$root\etc\configuration\readme.txt" "Not /etc/config. If the guard protects this, its prefix test is wrong.`n"

# The volume mount and the shares inside it — the real layout under /share.
foreach ($share in "Public", "Multimedia", "Web", "homes") {
    New-Dir "$root\share\CACHEDEV1_DATA\$share"
}
New-Dir "$root\share\CACHEDEV1_DATA\.qpkg\QNAPFileManager"
New-Dir "$root\share\CACHEDEV1_DATA\homes\sveinung"

Set-LinuxFile "$root\share\CACHEDEV1_DATA\Public\notes.txt" "hello from the fake NAS`n"
# A '#' and a space: the '#' has to survive URL encoding, and the space has to
# survive every path that is built by string concatenation.
Set-LinuxFile "$root\share\CACHEDEV1_DATA\Public\a #b.txt" "a name with a hash and a space`n"
Set-LinuxFile "$root\share\CACHEDEV1_DATA\Public\Bilder – 2024 ✓.txt" "a unicode name: en dash, a check mark`n"
Set-LinuxFile "$root\share\CACHEDEV1_DATA\Public\.hidden" "a dotfile`n"
New-Dir "$root\share\CACHEDEV1_DATA\Public\Sub folder"
Set-LinuxFile "$root\share\CACHEDEV1_DATA\Public\Sub folder\deep.txt" "one level down`n"

# A large-ish file, so the size column and the download path have something
# other than a few bytes to show.
$big = "$root\share\CACHEDEV1_DATA\Public\big.bin"
$fs = [System.IO.File]::Create($big)
try { $fs.SetLength(3MB) } finally { $fs.Close() }

# QTS lays out /share as a small tmpfs holding one symlink per registered
# shared folder, alongside the raw volume mount points themselves. Symlinks on
# Windows need Developer Mode or an elevated shell; without them the tree is
# still usable, it just cannot exercise the symlink paths.
$links = @{
    "Public"     = "CACHEDEV1_DATA\Public"
    "Multimedia" = "CACHEDEV1_DATA\Multimedia"
    "homes"      = "CACHEDEV1_DATA\homes"
}
$madeLinks = $true
foreach ($name in $links.Keys) {
    $link = "$root\share\$name"
    if (Test-Path $link) { continue }
    try {
        New-Item -ItemType SymbolicLink -Path $link -Target $links[$name] -ErrorAction Stop | Out-Null
    } catch {
        $madeLinks = $false
    }
}
if ($madeLinks) {
    # A dangling link, which List has to render without failing the whole
    # listing.
    try {
        New-Item -ItemType SymbolicLink -Path "$root\share\Gone" -Target "CACHEDEV1_DATA\NoSuchShare" -ErrorAction Stop | Out-Null
    } catch { $madeLinks = $false }
}
if (-not $madeLinks) {
    Write-Warning "Could not create symlinks under $root\share. Enable Windows Developer Mode or run this from an elevated shell to exercise the symlink paths; the rest of the tree is fine without them."
}

# Directories the guard must refuse to descend into, so the refusal itself can
# be exercised on Windows.
foreach ($d in "proc", "sys", "dev", "mnt\HDA_ROOT", "root", "tmp") {
    New-Dir "$root\$d"
}
Set-LinuxFile "$root\proc\readme.txt" "A stand-in. Nothing may walk into /proc.`n"

Write-Host "fakeroot ready at $root"
Write-Host "run: go run ./cmd/qnapfilemanager serve -config dev-config.json -jail testdata\fakeroot -addr 127.0.0.1:8899"
