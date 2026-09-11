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
	case "permission", "protected", "readonly", "read_only":
		return 403
	case "not_found":
		return 404
	case "exists", "not_empty", "cross_device", "conflict":
		return 409
	case "no_trash":
		// There is no same-device trash for this location, so the delete the
		// client asked for cannot be made reversible. It re-asks as a permanent
		// delete at confirmation level 2 (PLAN.md decision 10, ui-ux §4.4).
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
	case "audit_unavailable":
		// A mutation refused because its durable audit record could not be written
		// (adv 1): the daemon's own failure, so a 500.
		return 500
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
	s.fail(w, r, code, backendMessage(code), p, err.Error())
}
