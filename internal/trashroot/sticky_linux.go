package trashroot

// stickyEnforced is true where the sticky bit is real. On Linux — the only
// platform this app runs on for real — a trash directory without it would let
// any user rename any other user's deleted files, so its absence is an error
// rather than a detail.
const stickyEnforced = true
