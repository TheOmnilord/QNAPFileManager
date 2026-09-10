**no new defects**

The fix is complete by static inspection of commit `7836d875`:

- `splitOSPath` and `splitLink` preserve trailing separators as `dirMark`: [fsops.go:377](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:377), [fsops.go:474](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:474).
- `file/` retains the ENOTDIR-equivalent rejection (`ErrBadName` / `bad_request`): the marker forces classification, non-directories set `blocked`, and the marker returns it: [fsops.go:252](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:252), [fsops.go:201](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:201).
- `locked/` incurs no final search check; literal `locked/.` still calls `checkTraversable`, preserving EACCES: [fsops.go:183](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:183), [fsops.go:179](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:179).
- Absolute containment mapping excludes the sentinel from location/count calculations while retaining it for resolution: [fsops.go:327](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:327), [fsops.go:349](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:349). Via-link expansion preserves pending markers and the unchanged 40-hop limit: [fsops.go:258](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:258), [fsops.go:273](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:273).
- The marker branch introduces no descriptor acquisition or ownership changes, so no new fd leak is apparent: [fsops.go:183](/C:/Dev/QNAPFileManager/internal/fsops/fsops.go:183).

Regression coverage includes absolute/via-link directory requirements and unprivileged slash-versus-dot behavior: [fsops_test.go:1059](/C:/Dev/QNAPFileManager/internal/fsops/fsops_test.go:1059), [perm_linux_test.go:363](/C:/Dev/QNAPFileManager/internal/fsops/perm_linux_test.go:363).

Read-only review; tests were not run.