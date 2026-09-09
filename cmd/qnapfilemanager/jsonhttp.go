package main

import (
	"encoding/json"
	"net/http"
)

// apiError is the uniform error envelope from backend plan §4.2. The full
// version, with op and detail, arrives with internal/web; the shape is fixed
// here so nothing has to change on the UI side later.
type apiError struct {
	Error apiErrorBody `json:"error"`
}

type apiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Nothing here is cacheable: the session answer changes the moment the
	// operator signs in or out of QTS.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// The response is already committed by WriteHeader, so a marshalling
	// failure can only be logged, never turned into an error page.
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apiError{Error: apiErrorBody{Code: code, Message: message}})
}
