// why.js is the single source of every "why is this greyed out" sentence
// (M4 contract §7.1). One pure function, whyDisabled(action,ctx), over four
// causes, consulted by the three places that used to decide it separately: the
// toolbar, the context menu and the dialogs' primary buttons.
//
// It imports only perm.js, which is itself pure, so the whole table is testable
// in node with no DOM at all. The DOM side — disabled + aria-disabled + title +
// aria-describedby — is applyWhy in dom.js, because every control needs all
// four and three of them were being forgotten one control at a time.
//
// PRECEDENCE, and why it is not simply "first match wins":
//
//   readonly   (global)  certain
//   selection  (nothing selected, wrong kind, too many, listing not on screen)
//                        certain
//   capability (uid/gid arithmetic, perm.capsFor)
//                        a PREDICTION — INV-2
//   guard      (protected path class)
//                        certain, and the server's own words — and it is asked
//                        only of the MUTATING actions (Astra r1 #6)
//
// The contract ranks the causes in that order for REPORTING, and separately
// settles (§7.2) that a control whose only reason is `capability` stays
// ENABLED with an explanatory title: an ACL, a read-only mount or an immutable
// attribute can grant or refuse where the arithmetic says otherwise, so the
// kernel decides and the app only predicts (PLAN decision 12, INV-2).
//
// Those two rules meet when a control is both capability-hinted and
// guard-denied. Taking the ranking literally there would report the capability
// sentence — and, because capability does not disable, would leave a
// guard-denied control enabled. So the rule is stated once, here: among the
// causes that actually DISABLE (readonly, selection, guard) the ranking picks
// which one is reported; a capability cause is reported only when it is the
// only cause there is.
import {capsFor} from './perm.js';

// The four causes, in the contract's precedence order.
export const CAUSES = ['readonly', 'selection', 'capability', 'guard'];

// DISABLING are the causes that are certain enough to take a control away.
export const DISABLING = new Set(['readonly', 'selection', 'guard']);

// The sentences the contract fixes verbatim.
export const READONLY_SENTENCE =
 'Read-only mode is on, so nothing can be changed. An administrator can turn it off in Settings.';
// The listing is not on screen because the search results have replaced it. It
// is a selection-class reason — there is no visible selection to act on — and
// it must never be reported as read-only mode, which the user would go and
// check in Settings (round 1, finding 1).
export const PAUSED_SENTENCE = 'Close the search results to change files in this folder.';
export const SELECT_SENTENCE = 'Select a file or folder first.';
export const GUARD_SENTENCE = 'This location is protected and cannot be changed here.';

// KIND_SENTENCES answer "this is the wrong sort of thing". The `special` line
// is the contract's own example sentence.
export const KIND_SENTENCES = {
 dir: 'This is a folder, so it cannot be opened as a file. Download it as an archive instead.',
 broken: 'That symbolic link’s target is broken or unavailable, so there is nothing to open.',
 special: 'This is a device file, so it cannot be edited as text.',
 // A search hit's symlink was never followed, so the app does not know that it
 // is broken and must not say so (round 10).
 unfollowed: 'Search does not follow symlinks, so this one’s target was not inspected. Open its folder to see where it points.',
};

// ACTIONS is the table. Every mutating control in the app is a row, and so are
// the three read-only ones that can still be refused for the kind of thing
// selected — the point of one table is that nothing decides this on its own.
//
//   mutating  — subject to read-only mode and to the paused-listing gate
//   needs     — 'none' | 'one' | 'some'
//   kind      — 'readable' when the single selection must be a plain file
//   capability— true when perm.capsFor predicts whether the kernel will allow it
//   verb      — used in the "select one item to …" sentence
//   enabled   — the title the control carries when nothing is in the way
export const ACTIONS = {
 newFolder: {mutating: true, needs: 'none', enabled: 'New folder'},
 upload: {mutating: true, needs: 'none', enabled: 'Upload files into this folder (or drop them on the list)'},
 rename: {mutating: true, needs: 'one', verb: 'rename', enabled: 'Rename'},
 delete: {mutating: true, needs: 'some', enabled: 'Delete'},
 copy: {mutating: true, needs: 'some', enabled: 'Copy to another folder (Ctrl+C, then Ctrl+V)'},
 move: {mutating: true, needs: 'some', enabled: 'Move to another folder (Ctrl+X, then Ctrl+V)'},
 permissions: {mutating: true, needs: 'some', capability: true, enabled: 'Permissions (F9)'},
 trashRestore: {mutating: true, needs: 'some', selectionEmpty: 'Select items in Trash to restore.', enabled: 'Restore the selected items'},
 trashEmpty: {mutating: true, needs: 'some', selectionEmpty: 'The Trash is already empty.', enabled: 'Empty the Trash'},
 download: {mutating: false, needs: 'some', enabled: 'Download the selection'},
 viewText: {mutating: false, needs: 'one', kind: 'readable', verb: 'view', enabled: 'View this file as text (F4)'},
 properties: {mutating: false, needs: 'one', verb: 'inspect', enabled: 'Properties (Alt+Enter)'},
 search: {mutating: false, needs: 'none', enabled: 'Search this folder and below (Ctrl+F)'},
};

// capsSentence is the §7 capability line: the arithmetic's reason plus who the
// arithmetic was done for. props.js re-exports it as capsHint, so the
// permissions dialog and the toolbar say the same thing in the same words.
export function capsSentence(session, entry, caps) {
 const resolved = caps && typeof caps.reason === 'string'
  ? caps
  : capsFor(session?.uid, session?.groups, !!session?.rootMode, entry || {});
 if (!resolved.reason) return '';
 return `${resolved.reason} You are signed in as ${session?.user ?? 'this user'}.`;
}

// reasonsFor lists every applicable cause, in precedence order. Exported so a
// test can assert the ordering itself rather than only its consequence.
export function reasonsFor(action, ctx = {}) {
 const spec = ACTIONS[action];
 if (!spec) throw new Error(`whyDisabled: unknown action ${action}`);
 const count = Math.max(0, Math.floor(Number(ctx.count) || 0));
 // `one` is "exactly one item, and it is the one this action would act on" —
 // which is not the same as count === 1. Ctrl+Arrow moves focus without
 // changing the selection, and a toolbar action must never target a
 // focused-but-unselected row (round-3 finding 7); list.js decides that and
 // passes the answer in.
 const one = ctx.one === undefined ? count === 1 : !!ctx.one;
 const out = [];
 if (spec.mutating && ctx.readOnly) out.push({cause: 'readonly', sentence: READONLY_SENTENCE});
 // The paused listing and the selection itself are one cause with two
 // sentences: in both, there is nothing on screen this action could act on.
 if (spec.mutating && ctx.paused) out.push({cause: 'selection', sentence: PAUSED_SENTENCE});
 else if (spec.needs !== 'none' && count < 1) out.push({cause: 'selection', sentence: spec.selectionEmpty || SELECT_SENTENCE});
 else if (spec.needs === 'one' && !one) out.push({cause: 'selection', sentence: `Select one item to ${spec.verb || 'use this'}.`});
 else if (spec.kind === 'readable' && ctx.kind && ctx.kind !== 'file') out.push({cause: 'selection', sentence: KIND_SENTENCES[ctx.kind] || KIND_SENTENCES.special});
 // The arithmetic is only run over an entry there actually is. Asking capsFor
 // about nothing produces "Owned by uid NaN", which is worse than silence — and
 // a multi-item selection has no single owner to reason about, so list.js
 // passes the entry only when there is exactly one.
 const caps = ctx.caps && typeof ctx.caps.reason === 'string' && ctx.caps.reason
  ? capsSentence(ctx.session, ctx.entry, ctx.caps)
  : spec.capability && ctx.entry ? capsSentence(ctx.session, ctx.entry, null) : '';
 if (caps) out.push({cause: 'capability', sentence: caps});
 // The guard cause applies to MUTATING actions only (Astra r1 #6). A guard
 // denial is a refusal to CHANGE a protected region, never a refusal to look at
 // one: applying it to every row of the table disabled View, Download,
 // Properties and Search under /etc — taking away exactly the repair operations
 // an administrator opens this app to perform. Reads are the server's own call:
 // it answers 403 protected itself where it must (browse.go guardRead), and a
 // UI that greys the button first only hides that verdict behind a guess.
 if (spec.mutating && ctx.guard?.denied) out.push({cause: 'guard', sentence: ctx.guard.reason || GUARD_SENTENCE});
 return out;
}

// whyDisabled is the one question every control asks.
//
//   {allowed, cause, sentence, causes}
//
// `allowed` is whether the control may be pressed; `sentence` is what it says
// either way, so a caller never has to compose one. A capability-only verdict
// is allowed:true with cause:'capability' — enabled, with the explanation.
export function whyDisabled(action, ctx = {}) {
 const causes = reasonsFor(action, ctx);
 const blocking = causes.filter(entry => DISABLING.has(entry.cause));
 if (blocking.length) return {allowed: false, cause: blocking[0].cause, sentence: blocking[0].sentence, causes: causes.map(c => c.cause)};
 if (causes.length) return {allowed: true, cause: causes[0].cause, sentence: causes[0].sentence, causes: causes.map(c => c.cause)};
 return {allowed: true, cause: '', sentence: ACTIONS[action].enabled, causes: []};
}

// entryKind maps an entry to the one word whyDisabled needs, so the table never
// has to know what a symlink is. The predicates are badges.js's, passed in by
// the caller, because badges.js touches the DOM and this module must not.
export function entryKind({dir = false, readable = false, broken = false} = {}) {
 if (broken) return 'broken';
 if (dir) return 'dir';
 return readable ? 'file' : 'special';
}
