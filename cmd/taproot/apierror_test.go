package main

// apiError mirrors the JSON error envelope produced by internal/web so the
// command-level tests can decode it without importing the web package's
// internals.
type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Path    string `json:"path,omitempty"`
	} `json:"error"`
}
