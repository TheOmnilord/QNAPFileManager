# Third-party notices

QNAPFileManager is MIT-licensed (see `LICENSE`). The binary in the QPKG is built from this repository plus the
software below, whose licences require that their notices travel with a binary distribution. This file is shipped
inside the package next to the binary for that reason.

## The Go standard library and `golang.org/x/crypto`

The daemon is compiled with the Go toolchain's standard library, and it links `golang.org/x/crypto` (bcrypt, for
the break-glass password). Both are Copyright The Go Authors and distributed under the BSD-3-Clause licence below.

```
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Tailscale (documentation only)

`docs/research/qts-integration-facts.md` quotes a six-line Go struct from Tailscale's QNAP client
(https://github.com/tailscale/tailscale/blob/main/client/web/qnap.go, BSD-3-Clause, Copyright Tailscale Inc. & AUTHORS)
as a record of the `authLogin.cgi` response fields. No Tailscale code is in this repository's own sources or in the
binary: `internal/qtsauth` parses that response with its own lenient parser. The quotation is reproduced in the
research note under Tailscale's licence terms.
