// perm.js is the JavaScript mirror of internal/perm (M3 contract §1, §9). It is
// PURE — no DOM, no fetch, no imports — because everything the permissions
// dialog decides before it dispatches is decided here, and all of it has to be
// unit-testable on a Windows dev box where no kernel is involved (§14).
//
// The one representation is ModeSpec {mask, value}, applied as
// (cur &^ mask) | (value & mask). Absolute is mask 07777. That single shape is
// what makes three different things one mechanism (§1.1):
//
//   * a MIXED selection — the grid renders indeterminate checkboxes, and only
//     the bits the user actually touched enter the mask;
//   * a RECURSIVE apply over entries whose current modes this side has never
//     seen — there is no "current" to read, only bits to set and bits to clear;
//   * the three special-bit checkboxes — setuid/setgid/sticky are ordinary bits
//     in the same mask.
//
// Go is authoritative (internal/perm). This file mirrors it case for case, and
// internal/web/perm_test.mjs is the same table of cases the Go tests use.

// The bit groups, named once. Everything below is expressed in these.
export const ALL = 0o7777;        // an absolute set: every bit chmod can carry
export const PERM = 0o777;        // rwx for owner/group/other
export const SPECIAL = 0o7000;    // setuid | setgid | sticky
export const SETUID = 0o4000;
export const SETGID = 0o2000;
export const STICKY = 0o1000;

// BITS is the grid, in the order it is painted: three rows of three, then the
// three special bits. The id is the element id from ui-ux §3.5, so the dialog
// never spells a bit's identity twice.
export const BITS = [
 {id:'pOR',bit:0o400,label:'Owner read'},   {id:'pOW',bit:0o200,label:'Owner write'},   {id:'pOX',bit:0o100,label:'Owner execute'},
 {id:'pGR',bit:0o040,label:'Group read'},   {id:'pGW',bit:0o020,label:'Group write'},   {id:'pGX',bit:0o010,label:'Group execute'},
 {id:'pTR',bit:0o004,label:'Others read'},  {id:'pTW',bit:0o002,label:'Others write'},  {id:'pTX',bit:0o001,label:'Others execute'},
];
export const SPECIAL_BITS = [
 {id:'pSUID',bit:SETUID,label:'setuid'},
 {id:'pSGID',bit:SETGID,label:'setgid'},
 {id:'pSTICKY',bit:STICKY,label:'sticky'},
];

const u32 = n => (Number(n) >>> 0);
const specOf = spec => ({mask:u32(spec?.mask) & ALL,value:u32(spec?.value) & ALL});

// EMPTY is "nothing has been touched" — the spec a dialog opens with, and the
// spec a zero mask expresses for "apply to files only / folders only" (§1.2).
export const EMPTY = {mask:0,value:0};

// applySpec is the arithmetic, and the only place it is written.
export function applySpec(spec,cur) {
 const {mask,value} = specOf(spec);
 return u32((u32(cur) & ~mask) | (value & mask)) & ALL;
}

// setsSpecial mirrors ModeSpec.SetsSpecial: does this spec set any 07000 bit to
// ONE? Clearing them is not setting them, and the distinction is the whole rule
// of §1.3 — a recursive chmod may clear a special bit and may never set one.
export function setsSpecial(spec) {
 const {mask,value} = specOf(spec);
 return (mask & value & SPECIAL) !== 0;
}

// octal renders a mode the way perm.Octal does — four digits, zero padded
// ("0755", "2755", "7777") — so a mode this side prints and a mode the worker
// put in a Diff's Want/Got are spelled identically. Two spellings of one number
// in one dialog is how "did it work?" becomes unanswerable.
export function octal(mode) {
 return ((u32(mode) & ALL).toString(8)).padStart(4,'0');
}

// parseOctal reads what the user typed into #pOctal. It returns an ABSOLUTE
// spec (mask 07777) because typing a mode is saying what the mode should be —
// including the bits left out, which is exactly what "0755 clears setgid" means
// — or null when the text is not a mode at all.
export function parseOctal(text) {
 const raw = String(text ?? '').trim().replace(/^0o/i,'');
 // A leading zero is the conventional octal prefix, so "02755" and "2755" are
 // the same mode; five significant digits are not a mode at all.
 if (!/^0?[0-7]{1,4}$/.test(raw)) return null;
 return {mask:ALL,value:parseInt(raw,8)};
}

// symbolic mirrors perm.Symbolic: "drwxr-sr-x". It takes the type separately
// because a mode does not carry one.
export function symbolic(mode,dir) {
 const m = u32(mode) & ALL;
 const triple = (r,w,x,extra,letter) => {
  const on = !!(m & x), set = !!(m & extra);
  return (m & r ? 'r' : '-') + (m & w ? 'w' : '-') +
   (set ? (on ? letter : letter.toUpperCase()) : (on ? 'x' : '-'));
 };
 return (dir ? 'd' : '-') +
  triple(0o400,0o200,0o100,SETUID,'s') +
  triple(0o040,0o020,0o010,SETGID,'s') +
  triple(0o004,0o002,0o001,STICKY,'t');
}

// --- the grid over a selection ----------------------------------------------

// A dialog's model is the modes it was opened over plus the spec built so far.
// modes are the CURRENT modes of the selected entries; spec is what the user
// has touched. Nothing else is remembered, and the two views — grid and octal —
// are both rendered from this pair.
export function modelOf(entries) {
 const modes = (Array.isArray(entries) ? entries : []).map(e => parseOctal(e?.mode)?.value ?? 0);
 return {modes,spec:{...EMPTY}};
}

// bitState is a checkbox's three-way value: true (all set), false (all clear),
// null (mixed → indeterminate). A bit the user has TOUCHED is no longer mixed:
// the mask says it will be written, and the value says to what.
export function bitState(bit,{modes = [],spec = EMPTY} = {}) {
 const {mask,value} = specOf(spec);
 if (mask & bit) return (value & bit) !== 0;
 if (!modes.length) return false;
 const first = (u32(modes[0]) & bit) !== 0;
 return modes.every(m => ((u32(m) & bit) !== 0) === first) ? first : null;
}

// toggleBit records a click. The bit enters the mask whichever way it was
// moved: setting and clearing are both "the user decided this bit".
export function toggleBit(spec,bit,on) {
 const {mask,value} = specOf(spec);
 return {mask:u32(mask | bit) & ALL,value:u32(on ? value | bit : value & ~bit) & ALL};
}

// octalField is what #pOctal shows: the resulting mode when every selected
// entry would end up the same, and '' — rendered with the placeholder "mixed" —
// when they would not. A single entry therefore always has a number; a mixed
// selection gets one the moment the user types an absolute mode, because that
// makes the outcome the same for all of them.
export function octalField({modes = [],spec = EMPTY} = {}) {
 if (!modes.length) return octal(applySpec(spec,0));
 const results = modes.map(m => applySpec(spec,m));
 return results.every(r => r === results[0]) ? octal(results[0]) : '';
}

// symbolicField is the same answer in ls form, or '' when it is mixed.
export function symbolicField(model,dir) {
 const text = octalField(model);
 if (!text) return '';
 return symbolic(parseOctal(text).value,!!dir);
}

// --- smart X and the two job specs (§1.2) ------------------------------------

// The #pSmartX preset. It is CLIENT SIDE and the server has no mode of its own
// (§1.2): "use 0644 for files and 0755 for folders" is two ordinary ModeSpecs.
export const SMART_DIRS = {mask:PERM,value:0o755};
export const SMART_FILES = {mask:PERM,value:0o644};

export const APPLY_MODES = ['all','files','dirs'];

// jobSpecs turns one dialog state into the {files, dirs} pair a recursive job
// carries. Three rules, in this order:
//
//  1. #pSmartX replaces the PERMISSION bits with the preset — that is what the
//     checkbox means, and "recursive 0755" over a share is the classic way to
//     make every document executable.
//  2. Special bits the user explicitly CLEARED survive the preset. Clearing
//     setgid across a tree is the cleanup people actually need (§1.3), and the
//     preset's mask (0777) cannot express it. Special bits the user SET are
//     kept in the spec untouched so the server still refuses them as
//     bad_request — this side never silently drops a request the user made.
//  3. "Apply to files only / folders only" is a ZERO MASK on the other one.
export function jobSpecs({spec = EMPTY,apply = 'all',smartX = false} = {}) {
 const base = specOf(spec);
 const clears = base.mask & SPECIAL & ~base.value;   // touched special bits set to 0
 const merge = preset => ({
  mask:u32(preset.mask | clears) & ALL,
  value:u32(preset.value & ~clears) & ALL,
 });
 let files = smartX ? merge(SMART_FILES) : base;
 let dirs = smartX ? merge(SMART_DIRS) : base;
 if (smartX && setsSpecial(base)) {
  // A set special bit is still the user's request; carry it so the refusal is
  // the server's and not a silent edit of what they asked for.
  const sets = base.mask & base.value & SPECIAL;
  files = {mask:u32(files.mask | sets) & ALL,value:u32(files.value | sets) & ALL};
  dirs = {mask:u32(dirs.mask | sets) & ALL,value:u32(dirs.value | sets) & ALL};
 }
 if (apply === 'files') dirs = {...EMPTY};
 if (apply === 'dirs') files = {...EMPTY};
 return {files,dirs};
}

// specTouched says whether there is a mode change to send at all. A dialog
// opened and closed again must not post a no-op chmod.
export const specTouched = spec => (specOf(spec).mask & ALL) !== 0;

// recursiveSetsSpecial is the client's mirror of the server's bad_request
// (§1.3), so the dialog can say why rather than showing a 400.
export function recursiveSetsSpecial(specs) {
 return setsSpecial(specs?.files) || setsSpecial(specs?.dirs);
}
export const RECURSIVE_SPECIAL_REFUSAL =
 'A recursive change may clear setuid, setgid or sticky, but never set one. Clear the special boxes, or apply to this item alone.';

// --- capability hints (§5) ---------------------------------------------------

// capsFor mirrors perm.CapsFor. It is a pure function of the session and the
// entry the worker returned, and it is a HINT: an ACL, a read-only mount or an
// immutable attribute can grant or refuse where this arithmetic says otherwise,
// so the grid stays editable, Apply stays enabled, and the kernel decides
// (PLAN decision 12, superseding ui-ux §3.3 — §5.2).
export function capsFor(uid,groups,root,entry) {
 const owner = Number(entry?.uid);
 const isOwner = Number.isFinite(owner) && Number(uid) === owner;
 const caps = {
  chmod:!!root || isOwner,
  chownUID:!!root,
  chgrpTo:root ? null : (isOwner ? [...(groups || [])] : []),
  reason:'',
 };
 if (!caps.chmod) {
  const who = entry?.user ? `${entry.user} (uid ${owner})` : `uid ${owner}`;
  caps.reason = `Owned by ${who}. Only the owner or an administrator can change permissions.`;
 }
 return caps;
}

// --- the ACL badge (§6.3) ----------------------------------------------------

// The three sentences are VERBATIM from identity-and-hero-plan §4.4, quoted in
// contract §6.3. They are the reason the badge exists, so they are pinned here
// and asserted character for character in the tests.
export const ACL_POSIX_TEXT =
 'This item has an extended ACL that this app does not display. The mode below is only the base permission set — editing it will not remove the ACL.';
export const ACL_NFS4_TEXT =
 "This item's real permissions are an NFSv4 ACL. The mode shown is a summary the filesystem derives from it. Changing the mode may discard or reduce the ACL, and that cannot be undone from this app.";
export const ACL_UNKNOWN_TEXT = ACL_NFS4_TEXT + ' This app could not read the ACL to say more.';

// aclBadge is what the name cell and both dialogs show for an entry, or null
// when there is nothing to say. "none" is nothing to say; "nfs4-trivial" is
// nothing to say either — a trivial NFSv4 ACL describes exactly what the mode
// describes, which is why every object on a ZFS dataset does not get a badge
// (§6.1). "unknown" DOES get one, with the pessimistic text: a read or parse
// failure is never reported as "none".
export function aclBadge(entry) {
 switch (String(entry?.acl ?? '')) {
 case 'posix': return {state:'posix',glyph:'+',label:'Extended ACL (POSIX)',title:ACL_POSIX_TEXT};
 case 'nfs4': return {state:'nfs4',glyph:'⊕',label:'NFSv4 ACL',title:ACL_NFS4_TEXT};
 case 'unknown': return {state:'unknown',glyph:'?',label:'ACL could not be read',title:ACL_UNKNOWN_TEXT};
 default: return null;   // '', 'none', 'nfs4-trivial'
 }
}

// --- the post-call diff (§3) -------------------------------------------------

// diffText renders one perm.Diff{Field, Want, Got}. Two of the three cases
// identity plan §3.1 names have a sentence the UI shows verbatim; everything
// else states what was asked and what landed, which is all a diff ever means.
//
// The op matters because the SAME field means two different things: a setgid
// that did not take on a chmod is the kernel dropping a bit you may not set,
// and a setuid that is gone after a chown is the kernel doing what chown always
// does. Saying the second with the first's words would send an administrator
// looking for a group membership problem that is not there.
// diffField reads a Diff's field under either spelling, so nothing below has to
// know that the wire is `field` and the Go struct is `Field`.
export const diffField = diff => String(diff?.field ?? diff?.Field ?? '');

// SPECIAL_FIELDS are the three diffs that EXPLAIN a mode diff rather than
// standing beside it: when the kernel drops setgid, the mode landed elsewhere
// *because of that*, and the two are one fact.
export const SPECIAL_FIELDS = new Set(['setuid','setgid','sticky']);

export function diffText(diff,{op = 'chmod',group = ''} = {}) {
 const field = diffField(diff);
 const want = String(diff?.want ?? diff?.Want ?? '');
 const got = String(diff?.got ?? diff?.Got ?? '');
 const cleared = op === 'chown';
 switch (field) {
 case 'setgid':
  if (cleared) return 'The setgid bit was cleared by the change of owner — the kernel does this, and it cannot be kept.';
  return group
   ? `The setgid bit was not applied: you are not a member of group ${group}.`
   : 'The setgid bit was not applied: you are not a member of that group.';
 case 'setuid':
  return cleared
   ? 'The setuid bit was cleared by the change of owner — the kernel does this, and it cannot be kept.'
   : 'The setuid bit was not applied — the system refused it.';
 case 'sticky':
  return 'The sticky bit was not applied — the system refused it.';
 case 'mode':
  // Deliberately CAUSELESS. The same diff arrives from a groupmask chmod, from
  // a dropped setgid, and from an ACL the kernel reduced; naming one of them
  // here would be wrong in the other two cases, and the caller has the rest of
  // the list (or the server's own sentence) to say which it was.
  return `The mode was set to ${got}, not the ${want} that was asked for.`;
 case 'uid':
  return `The owner was not changed: ${want} was asked for, it is still ${got}.`;
 case 'gid':
  return `The group was not changed: ${want} was asked for, it is still ${got}.`;
 default:
  return field ? `${field}: asked for ${want}, got ${got}.` : 'The change did not land exactly as asked.';
 }
}

// diffTexts is the whole list, ORDERED AND THINNED so the first line is the one
// that explains the rest.
//
// The contract's own scenario is why. A non-member owner asks for 2755; the
// kernel writes 0755 and drops the setgid bit. DiffOf reports both halves —
// {mode 2755→0755} and {setgid on→off} — and rendering them in wire order put
// "the mode was set to 0755" first, which is true, unexplained, and the wrong
// half to lead with. The setgid sentence says WHY, and the mode line then adds
// nothing a reader cannot see from it, so it is dropped rather than repeated.
//
// A mode diff with no special-bit diff beside it (a groupmask chmod, an ACL the
// kernel reduced) keeps its line: there is nothing else to explain it.
export function diffTexts(diffs,context) {
 const list = (Array.isArray(diffs) ? diffs : []).filter(Boolean);
 const special = list.filter(d => SPECIAL_FIELDS.has(diffField(d)));
 const rest = list.filter(d => !SPECIAL_FIELDS.has(diffField(d)) && !(special.length && diffField(d) === 'mode'));
 return [...special,...rest].map(d => diffText(d,context));
}

// diffTone classifies a diff list for the caller's PRESENTATION — how sharply
// to say it — without deciding the words. A dropped special bit is the sharpest
// thing a permissions call can report and a mode or an id landing elsewhere is
// the ordinary one.
export function diffTone(diffs) {
 const fields = new Set((Array.isArray(diffs) ? diffs : []).filter(Boolean).map(diffField));
 if ([...SPECIAL_FIELDS].some(f => fields.has(f))) return 'special';
 if (fields.has('mode') || fields.has('uid') || fields.has('gid')) return 'mode';
 return fields.size ? 'other' : 'none';
}
// There was a diffSummary here that composed "<first> (and n more)" for the
// toast. Nothing calls it any more: reportResult stopped concatenating the two
// sides' sentences, so what the toast carries is the FIRST LINE of the list the
// dialog is displaying — perms.js showDiff — and a second way to compose that
// line is a second thing to keep true.

// --- the confirmation ladder, as far as this side can see it (§7) ------------

// The ladder itself is decided server-side, before dispatch, from the mount
// table — it must be, because a confirmation cannot be demanded after the
// change (§7). What reaches here is a challenge: `confirm.grade` beside the
// token (1 = L1, 2 = L2), a message, and a summary of warnings. permGrade
// decides how that challenge is PRESENTED.
//
// The server's own grade wins whenever it sends one, so this never argues with
// the ladder. The fallback is for the routes that predate M3 and send none: it
// is the part of §7 that is visible from a summary alone, and it fails towards
// 2 — the grade that asks for a typed phrase — because under-warning is the
// failure that costs an ACL.
export const PERM_L2_MARKERS = [/cannot be undone/i,/cannot be restored/i,/destroy/i,/permanent/i];

export function permGrade({grade,summary,recursive = false,protectedPath = false} = {}) {
 const s = summary || {},warnings = s.warnings || [];
 const declared = Number.isInteger(grade) ? grade : s.grade;
 if (declared === 1 || declared === 2) return declared;
 if (protectedPath) return 2;
 if (warnings.some(w => PERM_L2_MARKERS.some(re => re.test(String(w))))) return 2;
 if (recursive && Number(s.files || 0) > 500) return 2;
 return 1;
}

// --- the id pickers (§10) ----------------------------------------------------

// /api/ids answers with a bounded list; a domain user is not in it at all, so
// the dialog also accepts a TYPED NUMERIC id and shows the number when a name
// does not resolve. idItem normalises one row of the list, tolerating the
// uid/gid spellings as well as the plain one, and idLabel is how it reads.
export function idItem(row) {
 if (row == null) return null;
 const id = Number(row.id ?? row.uid ?? row.gid);
 if (!Number.isInteger(id)) return null;
 return {id,name:String(row.name ?? row.user ?? row.group ?? '')};
}
export const idItems = rows => (Array.isArray(rows) ? rows : []).map(idItem).filter(Boolean);
export function idLabel(item,kind = 'user') {
 if (!item) return '';
 const tag = kind === 'group' ? 'gid' : 'uid';
 return item.name ? `${item.name} (${tag} ${item.id})` : `${tag} ${item.id}`;
}

// ID_MAX is the largest id the routes accept: uid_t is 32 bits unsigned, and
// its top value (4294967295) is (uid_t)-1 — the kernel's own "leave this alone"
// — so 4294967294 is the last one that names an account. The bound is the
// routes' bound, stated here so the field refuses the number rather than
// posting it and reading back a bad_request.
export const ID_MAX = 4294967294;
export const ID_INVALID = 'Not a valid user or group id.';

// parseId reads the numeric field. It refuses anything that is not an integer
// in 0..ID_MAX: the routes refuse a negative id outright, and "leave this half
// alone" is an ABSENT key rather than a number a user could type.
export function parseId(text) {
 const raw = String(text ?? '').trim();
 if (!/^\d{1,10}$/.test(raw)) return null;
 const n = Number(raw);
 return Number.isSafeInteger(n) && n <= ID_MAX ? n : null;
}

// idProblem is what the dialog says about one id field. An unparseable field
// whose "change" box is ticked is an ERROR, not a silent no-op: applyPlan reads
// null as "this half is not changing", so without this a typo in the uid field
// would quietly apply nothing and report success.
export function idProblem(changing,text) {
 return changing && parseId(text) === null ? ID_INVALID : '';
}
