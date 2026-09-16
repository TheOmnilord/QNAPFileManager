const listeners = new Set();
// clipboard is the Ctrl+C / Ctrl+X marking: {mode:'copy'|'move',entries:[...]}
// or null. It is inert until a Ctrl+V, which opens the transfer dialog with it.
//
// searchResults is the last search's outcome — {query,root,detail,hits,open} or
// null — and it OUTLIVES the results view being closed. Following a hit into
// its folder must not be a one-way door: the walk that produced the hits can
// take a minute, so they are kept for the session and `open` says only whether
// the view is currently showing them.
//
// pendingReveal is a request from the results view to the listing: {name,path,
// pathB64} to select and focus once the folder it lives in has loaded. It is
// consumed exactly once, by loadList.
//
// searchJob is {seq,id} for the search that owns the results pane, or null. A
// search is a job that can run for a minute, so a second one can be submitted
// (and finish) while the first is still walking; only the latest may paint.
// `seq` is the SUBMISSION ticket, not the order the 202s came back in — see
// claimResults in search.js for why those are not the same order.
//
// listener is which listener answered /api/session — 'local' at the emergency
// door, '' or 'main' elsewhere. It is remembered because a 401 arriving later
// has no payload of its own, and it is what decides which sign-in is shown:
// the QTS notice must never appear on the emergency listener (M4 contract §2).
//
// dirClass is the listing's DISPLAY class of the CURRENT folder — 'protected',
// 'warn' or '' — a lexical hint from browse.go, not the guard's verdict. It
// drives the badge and the path notice only; it is NOT the `guard` cause of the
// reason table (Astra r1 #6: treating it as one disabled View, Download and
// Properties under /etc, exactly where an administrator repairs things). The
// empty state's "New folder" offer therefore stands there too, and the guard's
// own 403 — path-free, from the server — is the answer when it refuses; round 2,
// finding 2 (offering a button that 403s) is accepted for this class because
// the alternative hid a working control from the one user it exists for.
//
// listError is why the CURRENT folder has no rows, or null. An empty list and a
// list the kernel refused must never look the same (M4 contract §8.1), and the
// only place that difference is known is the failed request — so it is kept
// rather than reported once and thrown away.
export const state = {session:null,sessionGeneration:0,path:'/share',pathB64:'',sort:'name',desc:false,hidden:false,total:0,pages:new Map(),selection:new Set(),exclude:false,focus:0,anchor:0,filter:'',generation:0,loading:false,clipboard:null,searchResults:null,pendingReveal:null,searchJob:null,listError:null,listener:'',dirClass:''};
// Capture before awaiting: even signing back in as the same user invalidates old work.
export function sessionGuard() { const generation=state.sessionGeneration; return () => generation===state.sessionGeneration; }

// sameSession says whether a session is still the SAME USER's session, as
// distinct from being the same session OBJECT — which is what sessionGuard
// asks, and what every short operation should keep asking.
//
// The two questions come apart because the session object is REPLACED for
// reasons that have nothing to do with the user going away: settings.js
// re-reads it after a read-only toggle, and app.js re-reads it every minute and
// re-publishes it whenever anything in it differs. Each of those bumps the
// generation. For a request-and-a-dialog that is harmless — abandon it, the
// user can ask again. For an UPLOAD it was not: a ten-minute transfer was
// abandoned mid-stream by an unrelated toggle, its local job entry was never
// finished, and the Operations panel showed "running" for the rest of the
// session (round 6, finding 2).
//
// So sessionGuard keeps its strict meaning everywhere — transfer.js, search.js
// and every other short operation depend on it, and weakening it would be a
// change to all of them — and long-running local work asks this instead.
export function sameSession(before,now) {
 if (!before || !now) return false;
 return before.user===now.user && before.uid===now.uid;
}

// sessionTransition classifies a session replacement, so the app can tell the
// three of them apart instead of treating every change as a sign-in.
//
//   refresh — the same user, with different details (read-only toggled, a
//             rotated token, a first connect). Nothing is torn down.
//   signout — there is no session any more. Everything is torn down.
//   switch  — a DIFFERENT user. Everything is torn down, and must be.
//
// It exists because showSession routed every observed change through
// signInNotice(), which publishes `session:null` before installing the new
// session. That transient null is a synchronous notification, and subscribers
// act on it immediately: the upload teardown aborted the transfer and dropped
// the whole queue before sameSession ever got a chance to say "this is the same
// user". So a read-only toggle in ANOTHER TAB, noticed by the once-a-minute
// poll, killed an upload in this one (round 7). The fix is not to produce the
// transient at all.
export function sessionTransition(before,after) {
 if (!after) return 'signout';
 if (!before) return 'refresh';
 return sameSession(before,after) ? 'refresh' : 'switch';
}
export function update(patch) {
 if (Object.hasOwn(patch,'session')) state.sessionGeneration++;
 Object.assign(state,patch);
 for (const fn of listeners) fn(state);
}
export function subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); }
export const selected = index => state.exclude !== state.selection.has(index);
export const countSelected = () => state.exclude ? Math.max(0,state.total-state.selection.size) : state.selection.size;

// activeView says which pane is ON SCREEN. The listing and the search results
// share one pane, so this is the difference between "12 items are selected" and
// "12 items are selected somewhere nobody can see".
export function activeView(current) { return current?.searchResults?.open ? 'results' : 'listing'; }

// actionsEnabledFor is the gate every listing action passes through — the
// toolbar's enablement and every keyboard shortcut alike.
//
// It exists because a selection made in the listing SURVIVES a search, and
// while the results have replaced the listing that selection is invisible.
// Delete, Ctrl+X, Rename and Copy to… were all still live against it: rows the
// user could not see, could not check, and had probably forgotten. So in the
// results view the listing's selection counts as nothing and no mutation is
// offered at all; the results view has its own focused row, and the actions
// that can honestly act on one item (download, view, properties) are pointed at
// that instead.
//
// Pure, so the rule is unit-tested rather than inferred from a screenshot.
export function actionsEnabledFor(view,selection) {
 if (view === 'results') return {view:'results',listing:false,mutate:false,count:0};
 return {view:'listing',listing:true,mutate:true,count:Math.max(0,Math.floor(Number(selection)) || 0)};
}

// listingActions is the gate for the CURRENT state, for the many callers that
// only need the answer.
export const listingActions = () => actionsEnabledFor(activeView(state),countSelected());
