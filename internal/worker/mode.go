package worker

// The M3 handlers: chmod, chown and properties, plus the two recursive job
// kinds. Each one is a thin translation between the wire and fsops, which is
// where the descriptor discipline and the kernel's verdict live.

import (
	"context"
	"fmt"

	"qnapfilemanager/internal/fsops"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// chmod changes one entry's mode as the user and replies with the before, the
// after and the difference between what was asked and what the kernel did.
//
// req.Follow is the ROUTE's flag, not this one's: with it set the route resolved
// the symlink itself and re-guarded the target as a path of its own, so what
// arrives here is already the target. A symlink reaching this handler is
// therefore refused whatever the flag says, and fsops is where that happens —
// Linux has no lchmod, and there is no second opinion to have about it.
func (s *session) chmod(ctx context.Context, f wproto.Frame) {
	var req wproto.ChmodReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	resp, err := fsops.Chmod(ctx, s.root, s.plat, string(req.Path), req.Spec)
	if err != nil {
		s.replyErr(f.ID, err, req.Path)
		return
	}
	s.replyOK(f.ID, resp)
}

// chown changes one entry's owner and/or group as the user. It is always an
// lchown, so req.Follow — which would mean "reach through the link" — is refused
// rather than implemented: one chown semantics, and no path on which a symlink
// is silently followed (M3 contract §1.4).
func (s *session) chown(ctx context.Context, f wproto.Frame) {
	var req wproto.ChownReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	if req.Follow {
		s.replyErr(f.ID, fmt.Errorf(
			"chown always changes a symlink's own ownership and never its target's: %w", fsx.ErrUnsupported), req.Path)
		return
	}
	resp, err := fsops.Chown(ctx, s.root, s.plat, string(req.Path), req.UID, req.GID)
	if err != nil {
		s.replyErr(f.ID, err, req.Path)
		return
	}
	s.replyOK(f.ID, resp)
}

// props answers the properties dialog. Like the trash listing and the move
// pre-flight it is a plain request rather than a job: it is one walk, one fstat,
// one fstatfs and one attribute read, and the dialog needs all of it at once.
// The directory SIZE it shows is the existing size job, submitted and polled by
// the front end; there is no second size implementation behind this call.
//
// req.Follow is inert. A symlink's target is described only from req.Target —
// the route's own resolved, guarded spelling — because resolving the link HERE
// would describe whatever the link points at now rather than what the guard
// passed (round-3 review). A request with Follow and no Target simply gets no
// target, which is also the honest answer for a dangling one.
func (s *session) props(ctx context.Context, f wproto.Frame) {
	var req wproto.PropsReq
	if err := f.Unmarshal(&req); err != nil {
		s.replyErr(f.ID, err, nil)
		return
	}
	resp, err := fsops.Props(ctx, s.root, s.plat, string(req.Path), string(req.Target))
	if err != nil {
		s.replyErr(f.ID, err, req.Path)
		return
	}
	s.replyOK(f.ID, resp)
}
