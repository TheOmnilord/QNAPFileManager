package web

import (
	"encoding/json"
	"net/http"
	"qnapfilemanager/internal/fsx"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func statusCode(code string) int {
	switch code {
	case "bad_request", "ramdisk":
		return 400
	case "unauthorized":
		return 401
	case "permission", "protected", "readonly":
		return 403
	case "not_found":
		return 404
	case "exists", "not_empty", "cross_device", "conflict":
		return 409
	case "too_large":
		return 413
	case "unsupported":
		return 415
	case "queue_full":
		return 429
	case "worker_gone":
		// The worker died mid-request; the pool respawns it, so retrying is right.
		return 503
	case "no_space":
		return 507
	case "confirm_required":
		return 428
	case "cancelled":
		return 408
	default:
		return 500
	}
}

func writeError(w http.ResponseWriter, status int, code, message, path, op, detail string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message, "path": path, "op": op, "detail": detail}})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, code, message, path, detail string) {
	s.logger.Printf("request ip=%q method=%s op=%q code=%s path=%q", ClientIP(r), r.Method, r.URL.Path, code, path)
	writeError(w, statusCode(code), code, message, path, r.URL.Path, detail)
}

func (s *Server) backendError(w http.ResponseWriter, r *http.Request, p string, err error) {
	code := fsx.Code(err)
	messages := map[string]string{"permission": "Permission denied.", "not_found": "This path no longer exists.", "readonly": "This filesystem is read-only.", "unsupported": "This file cannot be opened here.", "internal": "The filesystem request failed."}
	msg := messages[code]
	if msg == "" {
		msg = "The request could not be completed."
	}
	s.fail(w, r, code, msg, p, err.Error())
}
