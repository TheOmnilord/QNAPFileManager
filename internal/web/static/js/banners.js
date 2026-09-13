// banners.js is the two persistent bars above the list (M4 contract §8.3/§8.4).
//
// Both are STATE, not events: they are on for as long as the state is on, they
// are never dismissible, and they are announced once when they change — not on
// every navigation, which is what turns a live region into noise.
//
// Pure — no DOM, no imports — so "which bars does this session show" is a unit
// test over a session object. app.js paints what this returns.

// The doors a session can have come in through (contract §6.1, §10). The UI
// branches on exactly one of them, `local`, and pins all three so a fourth
// spelling on the wire is a test failure rather than a silently missing banner.
export const DOORS = ['qts', 'credential', 'local'];
export const BREAK_GLASS_DOOR = 'local';

// The wording is the contract's, verbatim. It is the one sentence standing
// between an operator and a support tree full of root-owned files nobody else
// can delete (§2.4, §18.5), so it is pinned and asserted character for
// character.
// One literal, not two joined by a +, so the sentence can be pinned verbatim
// from the Go side as well (internal/web/ui_door_pin_test.go).
export const BREAK_GLASS_TEXT = 'Emergency access. You are signed in with the local administrator account, not a QTS user. Everything you create here will be owned by root.';
export const READONLY_TEXT = 'Read-only mode — no changes can be made.';
export const READONLY_ADMIN_TAIL = 'You can turn it off in Settings.';
export const READONLY_USER_TAIL = 'Ask an administrator to turn it off in Settings.';

// banners returns the bars a session shows, in painting order (read-only first:
// it is the one that says what will happen to the next click).
//
// Each bar is {id, kind, text, tail, action} — `action` is an inline control,
// offered only to someone who could actually use it. Offering a non-admin a
// button that would 403 is worse than telling them who to ask.
export function banners(session) {
 if (!session) return [];
 const out = [];
 // canWrite is the server's own answer ("!readOnly" for an authenticated
 // session), so the bar follows the thing that actually refuses the write
 // rather than a second copy of the rule.
 const readOnly = session.readOnly ?? !session.canWrite;
 if (readOnly) {
  out.push({
   id: 'bannerReadonly',
   kind: 'readonly',
   text: READONLY_TEXT,
   tail: session.admin ? READONLY_ADMIN_TAIL : READONLY_USER_TAIL,
   action: session.admin ? {id: 'bannerReadonlySettings', label: 'Open Settings'} : null,
  });
 }
 if (String(session.door || '') === BREAK_GLASS_DOOR) {
  out.push({id: 'bannerBreakGlass', kind: 'warn', text: BREAK_GLASS_TEXT, tail: '', action: null});
 }
 return out;
}

// identityLabel is what the Session dialog calls this sign-in.
//
// It is keyed on the DOOR, not on `viaQTS`: a break-glass session has no QTS
// `kind`, so viaQTS is false, and the dialog therefore described an emergency
// administrator session as a "Pinned development identity" — on the one door
// where knowing exactly what you are signed in as matters most (round 1,
// finding 4).
export function identityLabel(session) {
 if (String(session?.door || '') === BREAK_GLASS_DOOR) return 'Emergency access (local administrator)';
 return session?.viaQTS ? 'QTS session' : 'Pinned development identity';
}

// bannerSignature is what "changed" means for the announcement. Two navigations
// inside the same read-only session produce the same signature and are
// therefore announced once, which is the whole of §8.3's "announced once on
// change and not on every navigation".
export function bannerSignature(list) {
 return (list || []).map(bar => `${bar.id}:${bar.text} ${bar.tail}`.trim()).join(' | ');
}
