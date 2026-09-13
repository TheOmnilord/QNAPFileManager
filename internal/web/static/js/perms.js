import {api} from './api.js';
import {$,el,error,announce,applyWhy,openDialog,pathArgs,toast} from './dom.js';
import {whyDisabled} from './why.js';
import {state,sessionGuard,listingActions,subscribe} from './state.js';
import {isDirectory,isSymlink,hasTarget,fileTarget} from './badges.js';
import {runMutation,confirmDialog,actionMessage} from './actions.js';
import {trackJob} from './jobs.js';
import {loadList,selectionEntries,activeSelection,extraActions} from './list.js';
import {loadTree} from './tree.js';
import {createSizeRunner,propsTarget,capsHint} from './props.js';
import {
 ALL,APPLY_MODES,BITS,SPECIAL_BITS,EMPTY,
 aclBadge,applySpec,bitState,diffTexts,diffTone,idItems,idLabel,idProblem,jobSpecs,octal,octalField,parseId,parseOctal,
 permGrade,recursiveSetsSpecial,RECURSIVE_SPECIAL_REFUSAL,setsSpecial,specTouched,symbolicField,toggleBit,
} from './perm.js';

// The Permissions dialog (#dlgPerms, F9 — ui-ux §3.5, M3 contract §12).
//
// Everything above the "--- the dialog" line is pure: the request bodies, the
// impact sentence and the confirmation grade. That is deliberate. A chmod is
// one of the two operations in this app that can make a NAS unusable without
// failing — the other is chown — and "what exactly did that button post" has to
// be answerable from a test rather than from a packet capture.

// --- what Apply posts --------------------------------------------------------

// applyPlan is the whole dispatch decision, as data.
//
// Sync when it is ONE item and not recursive; a job otherwise (§10, backend
// plan §5). Chown is posted BEFORE chmod when both are asked for, because the
// kernel clears setuid — and setgid on a group-executable file — on a change of
// owner (§3.2). Running chmod first would mean the mode the user typed was
// silently undone by the very next request, and the diff would report it
// truthfully while the end state was still wrong.
//
// A chown sends ONLY the half it is changing: ABSENT = UNCHANGED. The routes
// read uid and gid as *int (routes_perm.go chownIDs) and refuse a negative
// number outright, so the "leave this alone" sentinel is never spelled on the
// wire at all — while an explicit 0 is root, a real target that must stay
// sendable and must never be confused with an absent key.
export function applyPlan({
 entries,spec = EMPTY,owner = null,group = null,
 recursive = false,apply = 'all',smartX = false,crossMounts = false,follow = false,
} = {}) {
 const list = (Array.isArray(entries) ? entries : []).filter(Boolean);
 if (!list.length) return [];
 const single = list.length === 1 && !recursive;
 const paths = list.map(pathArgs);
 const requests = [];
 if (owner !== null || group !== null) {
  const ids = {};
  if (owner !== null) ids.uid = owner;
  if (group !== null) ids.gid = group;
  requests.push(single
   ? {op:'chown',endpoint:'api/fs/chown',body:{...paths[0],...ids}}
   : {op:'chown',endpoint:'api/jobs/chown',body:{paths,...ids,recursive:!!recursive,crossMounts:!!crossMounts},job:true});
 }
 // A recursive smart-X IS a change even when no box was ticked: "apply 0644 to
 // the files and 0755 to the folders below this" is the whole request, and the
 // preset — not the grid — is what expresses it.
 if (specTouched(spec) || (recursive && smartX)) {
  if (single) {
   const body = {...paths[0],mask:spec.mask & ALL,value:spec.value & ALL};
   // chmod never touches a symlink (§1.4): the route refuses one as
   // `unsupported` unless follow is passed and it re-guards the resolved target.
   if (follow) body.follow = true;
   requests.push({op:'chmod',endpoint:'api/fs/chmod',body});
  } else {
   // applyScope again, at the wire: the radios describe what happens to a
   // folder's CONTENTS, so a non-recursive job never reads them.
   const {files,dirs} = jobSpecs({spec,apply:applyScope(recursive,apply),smartX:smartX && recursive});
   requests.push({op:'chmod',endpoint:'api/jobs/chmod',
    body:{paths,files,dirs,recursive:!!recursive,crossMounts:!!crossMounts},job:true});
  }
 }
 return requests;
}

// permsApplies is the line under the title: what this dialog is about to change
// and whether their current modes agree.
export function permsApplies(entries,modes = []) {
 const list = (Array.isArray(entries) ? entries : []).filter(Boolean);
 if (!list.length) return 'Nothing selected.';
 if (list.length === 1) return `1 ${isDirectory(list[0]) ? 'folder' : 'file'} — ${list[0].name}`;
 const dirs = list.filter(isDirectory).length,files = list.length-dirs;
 const mixed = modes.length > 1 && !modes.every(m => m === modes[0]);
 return `${list.length.toLocaleString()} items — ${dirs} folder(s), ${files} file(s)${mixed ? ' · mixed permissions' : ''}`;
}

// impactRoots is WHAT #pImpact measures, which is not always what was selected.
//
// Every QTS share is a symlink: /share/Public → /share/CACHEDEV1_DATA/Public.
// A recursive change follows the selected root to its target — that is the
// whole point of chmod-ing a share — but a size job pointed at the LINK counts
// one file, so the dialog would have promised "1 item" before changing eight
// thousand. So a recursive measurement is taken on the resolved spelling the
// listing already carries.
//
// A link whose target never resolved has no spelling to measure, and the
// honest answer is to say so rather than to show the 1 the link itself weighs.
export function impactRoots(entries,{recursive = false} = {}) {
 const roots = [],unmeasured = [];
 for (const entry of (Array.isArray(entries) ? entries : []).filter(Boolean)) {
  if (recursive && isSymlink(entry) && entry.targetType === 'dir') {
   if (hasTarget(entry)) roots.push(fileTarget(entry));
   else unmeasured.push(entry.name);
   continue;
  }
  roots.push(entry);
 }
 return {roots,unmeasured};
}

// impactNote names what could not be measured, so an absent count is an answer
// rather than a silence.
export function impactNote(unmeasured) {
 const names = (unmeasured || []).filter(Boolean);
 if (!names.length) return '';
 return `The size of the linked folder was not measured for ${names.join(', ')}.`;
}

// impactText is #pImpact: the measured scale of a recursive change, from the
// size job (§8.4). It never guesses — an unfinished or cancelled measurement
// says so in the job's own words.
export function impactText(report) {
 if (!report) return '';
 if (report.state !== 'done') return report.text || '';
 const r = report.result || {};
 const files = Number(r.files || 0),dirs = Number(r.dirs || 0);
 return `Will change ${(files+dirs).toLocaleString()} items (${files.toLocaleString()} files, ${dirs.toLocaleString()} folders).`;
}

// --- the dialog --------------------------------------------------------------

let model = {modes:[],spec:{...EMPTY}};
let targets = [];
// idCache holds one answer from /api/ids, and it is keyed on the SESSION that
// asked for it. /api/ids is narrowed server-side — an admin gets the full local
// roster, anybody else only their own user and their own groups (§10) — so a
// cache that outlived a session handed the next user the previous one's lists.
// showSession replaces the session in place for a change of user, nothing tears
// this module down, and the pickers would then have rendered an admin's roster
// to a non-admin: exactly the disclosure the narrowing exists to prevent.
let idCache = null;
export function clearIdCache() { idCache = null; }

// unmeasured is what the current measurement could NOT include (a share symlink
// whose target does not resolve), kept beside the runner so every repaint of
// #pImpact carries the caveat with the number.
let unmeasured = [];
const impactRunner = createSizeRunner({report:report => {
 $('#pImpact').textContent = [impactText(report),impactNote(unmeasured)].filter(Boolean).join(' ');
}});

// startImpact measures whatever the CURRENT recursive setting means (see
// impactRoots): the link for a plain chmod, the target for a recursive one.
function startImpact() {
 const {roots,unmeasured:skipped} = impactRoots(targets,{recursive:recursive()});
 unmeasured = skipped;
 if (!roots.length) { impactRunner.stop(); $('#pImpact').textContent = impactNote(unmeasured); return; }
 impactRunner.start(roots,{crossMounts:state.session?.family === 'quts_hero'});
}

const checkbox = id => $(`#${id}`);
const recursive = () => $('#pRecursive').checked;
// applyScope is the apply-to choice, and it is 'all' whenever the change is not
// recursive — the radios describe what happens to the CONTENTS of a folder, and
// there are no contents in a non-recursive change. Pure, so the rule is tested
// rather than inferred from whether a disabled radio kept its dot.
export function applyScope(isRecursive,checked) {
 return isRecursive && APPLY_MODES.includes(checked) ? checked : 'all';
}
const checkedScope = () => ($('#pApplyFiles').checked ? 'files' : $('#pApplyDirs').checked ? 'dirs' : 'all');
const applyMode = () => applyScope(recursive(),checkedScope());

// paintGrid repaints the twelve boxes and the symbolic rendering. writeOctal is
// false while the OCTAL FIELD ITSELF is what changed: rewriting the input the
// user is typing into would move the caret on every keystroke, so "75" would
// become "0075" with the cursor at the end before the third digit arrived.
function paintGrid(writeOctal = true) {
 for (const {id,bit} of [...BITS,...SPECIAL_BITS]) {
  const box = checkbox(id),value = bitState(bit,model);
  box.indeterminate = value === null;
  box.checked = value === true;
 }
 const dir = targets.length === 1 ? isDirectory(targets[0]) : targets.some(isDirectory);
 if (writeOctal) $('#pOctal').value = octalField(model);
 $('#pSymbolic').textContent = symbolicField(model,dir) || 'mixed';
}

function paintRecursive() {
 const on = recursive();
 for (const id of ['pApplyAll','pApplyFiles','pApplyDirs','pSmartX']) $(`#${id}`).disabled = !on;
 // A DISABLED radio keeps its .checked, so "Folders only" chosen while
 // recursive, then un-ticked, left the scope silently selected: a multi-item
 // apply over files then posted files:{mask:0} and came back "changed 0 of N,
 // N skipped" for a change the user watched themselves make. The control is
 // reset as well as disabled, and applyScope refuses to read it either way.
 if (!on) $('#pApplyAll').checked = true;
 // #pFollowLinks is a single-item option only: a recursive walk NEVER follows a
 // symlink (§1.4, ui-ux §4.5 item 4), so offering the choice there would be
 // offering something the server refuses by design.
 const one = targets.length === 1 && !on;
 $('#pFollowLinks').disabled = !one || !isSymlink(targets[0]);
 if ($('#pFollowLinks').disabled) $('#pFollowLinks').checked = false;
 $('#pRecursiveNote').hidden = !on;
}

function paintWarnings() {
 const entry = targets[0] || {};
 const badge = targets.map(aclBadge).find(Boolean);
 $('#pAcl').textContent = badge ? badge.title : '';
 $('#pAcl').hidden = !badge;
 const hint = capsHint(state.session,entry,null);
 $('#pCaps').textContent = hint; $('#pCaps').hidden = !hint;
 const specs = recursive() ? jobSpecs({spec:model.spec,apply:applyMode(),smartX:$('#pSmartX').checked}) : null;
 const refuse = specs && recursiveSetsSpecial(specs);
 $('#pWarn').textContent = refuse ? RECURSIVE_SPECIAL_REFUSAL
  : recursive() ? 'A recursive permission change cannot be undone, and cancelling it leaves the tree half-changed.' : '';
 $('#pWarn').hidden = !$('#pWarn').textContent;
 refreshApply();
}

// applyBlocked is the ONE rule for whether Apply may be pressed, as data.
//
// It is one function because it used to be two places that disagreed:
// paintWarnings disabled the button for a recursive special-bit SET, and
// applyNow's `finally` re-enabled it unconditionally — so a refused request
// left the dialog offering to send it again, and the second press went through
// the same refusal with the warning still on screen. Every repaint and every
// end of an attempt now asks this instead of setting the property itself.
export function applyBlocked({applying = false,canWrite = true,recursive = false,specs = null} = {}) {
 if (applying) return 'applying';
 if (!canWrite) return 'readOnly';
 if (recursive && recursiveSetsSpecial(specs)) return 'special';
 return '';
}

// applying is true while a plan is in flight, so the button cannot be pressed
// twice into the same dialog.
let applying = false;

function currentSpecs() {
 return jobSpecs({spec:model.spec,apply:applyMode(),smartX:$('#pSmartX').checked});
}

function refreshApply() {
 const blocked = applyBlocked({
  applying,canWrite:state.session ? !!state.session.canWrite : true,
  recursive:recursive(),specs:currentSpecs(),
 });
 // The dialog's primary button goes through the shared reason table (M4
 // contract §7.1) so read-only mode says here exactly what it says on the
 // toolbar; `blocked` carries the dialog's own reasons (a request in flight, a
 // recursive change that would SET a special bit), which the table does not
 // know about and must not be asked to.
 const verdict = whyDisabled('permissions',{
  readOnly:state.session ? !state.session.canWrite : false,
  count:targets.length,
  // The capability hint is shown by #pCaps; the button stays ENABLED for it,
  // because the kernel decides and the arithmetic only predicts (INV-2).
  entry:null,session:state.session,
 });
 // Each of the dialog's own reasons in its own words: a button grey because a
 // request is in flight must not describe itself as ready (round 1, finding 2).
 const pending={
  applying:'The change is being sent.',
  readOnly:'',   // the verdict says this one, and says it better
  special:RECURSIVE_SPECIAL_REFUSAL,
 }[blocked] ?? '';
 applyWhy('#pApply',verdict,blocked ? pending || true : '');
}

function repaint() { paintGrid(); paintRecursive(); paintWarnings(); }

function ownerValue() { return $('#pOwnerChange').checked ? parseId($('#pOwnerId').value) : null; }
function groupValue() { return $('#pGroupChange').checked ? parseId($('#pGroupId').value) : null; }

// idErrors is the two id fields checked together. A ticked box with an
// unreadable number is an error and not a no-op: applyPlan reads null as "this
// half is not changing", so a typo would otherwise apply nothing and say it
// worked.
function idErrors() {
 return [
  idProblem($('#pOwnerChange').checked,$('#pOwnerId').value) && `Owner: ${idProblem(true,$('#pOwnerId').value)}`,
  idProblem($('#pGroupChange').checked,$('#pGroupId').value) && `Group: ${idProblem(true,$('#pGroupId').value)}`,
 ].filter(Boolean);
}

function paintIdErrors() {
 const problems = idErrors();
 $('#permsError').textContent = problems.join(' ');
 $('#permsError').hidden = !problems.length;
 return problems;
}

// loadIds fills the two pickers. /api/ids is narrowed server-side — an admin
// gets the local lists, a non-admin only their own user and their own groups
// (§10) — so whatever comes back is exactly what this session may set.
//
// It lists /etc/passwd and /etc/group only: there is no bulk NSS API, and
// `getent passwd` on a domain-joined NAS is both enormous and slow. A domain
// user is therefore in NEITHER list, which is why the numeric field beside each
// picker is not a fallback but the documented way in — and why a truncated list
// says so rather than looking complete.
//
// `q` is the route's prefix filter. It is passed through (and cached per
// prefix) so the bound is reachable; nothing in the dialog drives it yet,
// because a <select> has no server-side type-ahead to drive it with.
//
// The cache is keyed on the session GENERATION as well as the prefix: a
// different session must never be shown another session's lists, and that is
// not a refinement of the bound — it is the narrowing itself.
export async function loadIds(q = '') {
 const generation = state.sessionGeneration;
 if (idCache && idCache.q === q && idCache.generation === generation) return idCache;
 const valid = sessionGuard();
 const out = {generation,q,users:[],groups:[],truncated:false};
 try {
  for (const kind of ['users','groups']) {
   const data = await api('api/ids',q ? {kind,q} : {kind});
   if (!valid()) return out;
   out[kind] = idItems(data.items);
   if (data.truncated) out.truncated = true;
  }
 } catch { /* the pickers degrade to the numeric fields, which always work. */ }
 idCache = out;
 return out;
}

function fillPicker(select,items,kind,current) {
 select.replaceChildren(el('option',{value:''},'— choose —'));
 for (const item of items) select.append(el('option',{value:String(item.id)},idLabel(item,kind)));
 if (current !== null && current !== undefined && !items.some(i => i.id === current)) {
  select.append(el('option',{value:String(current)},idLabel({id:current,name:''},kind)));
 }
 select.value = current === null || current === undefined ? '' : String(current);
}

// openPerms is the dialog's one entry point. Everything it needs it is handed:
// the entries. It does not reach into the listing, so the toolbar, the context
// menu, F9 and the Properties footer all open the same dialog the same way.
export async function openPerms(entries) {
 const list = (Array.isArray(entries) ? entries : [entries]).filter(Boolean);
 if (!list.length) return;
 targets = list;
 model = {modes:list.map(e => parseOctal(e?.mode)?.value ?? 0),spec:{...EMPTY}};
 $('#permsTitle').textContent = `Permissions — ${list.length === 1 ? (list[0].path || list[0].name) : `${list.length} items`}`;
 $('#permsApplies').textContent = permsApplies(list,model.modes);
 $('#pRecursive').checked = false;
 $('#pApplyAll').checked = true;
 // #pSmartX is ON by default for a recursive change: "recursive 0755" is the
 // classic way to ruin a share, and 0644/0755 is what people actually mean.
 $('#pSmartX').checked = true;
 $('#pFollowLinks').checked = false;
 $('#pOwnerChange').checked = false; $('#pGroupChange').checked = false;
 $('#pOwnerId').value = String(list[0].uid ?? ''); $('#pGroupId').value = String(list[0].gid ?? '');
 $('#pDiff').textContent = ''; $('#pDiff').hidden = true;
 $('#permsError').textContent = ''; $('#permsError').hidden = true;
 $('#pImpact').textContent = '';
 applying = false;
 ownerEnabled(); repaint();
 openDialog('#dlgPerms');
 $('#pOctal').focus?.();
 const ids = await loadIds();
 if (!$('#dlgPerms').open) return;
 fillPicker($('#pOwner'),ids.users,'user',list[0].uid ?? null);
 fillPicker($('#pGroup'),ids.groups,'group',list[0].gid ?? null);
 // A list that was cut short, or an empty one, must not look complete: the
 // number is always accepted, and on a domain-joined unit it is the only way to
 // name somebody /etc/passwd has never heard of.
 const short = ids.truncated || !ids.users.length || !ids.groups.length;
 $('#pIdsNote').textContent = short
  ? 'Not every account is listed here. Type a numeric uid or gid to use one that is not.'
  : '';
 $('#pIdsNote').hidden = !short;
 if (list.some(isDirectory)) startImpact();
}

function ownerEnabled() {
 for (const [box,select,field] of [['pOwnerChange','pOwner','pOwnerId'],['pGroupChange','pGroup','pGroupId']]) {
  const on = $(`#${box}`).checked;
  $(`#${select}`).disabled = !on; $(`#${field}`).disabled = !on;
 }
}

// askPermConfirm shows the SERVER's sentences. The ladder is decided before
// dispatch, on the side that holds the mount table (§7); this side only decides
// how loudly to ask — and a grade 2 asks for the item's name to be typed, the
// same gesture a permanent delete asks for.
function askPermConfirm(confirm,message,ctx) {
 const summary = confirm?.summary || {};
 const grade = permGrade({grade:confirm?.grade,summary,recursive:ctx.recursive,protectedPath:ctx.protectedPath});
 return confirmDialog({
  title:ctx.op === 'chown' ? 'Confirm change of owner' : 'Confirm permission change',
  body:message || 'This change needs confirmation.',
  why:(summary.warnings || []).join(' · '),
  danger:grade === 2,
  phrase:grade === 2 ? ctx.phrase : '',
  okLabel:'Apply',
 });
}

// reportResult is §3.3 and §12 in one place: a call that succeeded WITH a diff
// is a 200 and a WARNING — never a success toast — and the sentence stays in
// the dialog after the toast has gone, because "the setgid bit was not applied"
// is not something to read for three seconds and lose.
//
// The SERVER's sentences are what is displayed whenever it sent any. It knows
// the group, the dataset and the aclmode; this side knows only the numbers. The
// old version concatenated both and de-duplicated by string equality, which
// cannot work — the two sides word the same fact differently, so a dropped
// setgid was reported twice, in two voices, one of them blaming an ACL.
//
// The diffs are still read, for TONE alone: how sharply to say it, never what
// to say. They are the fallback text only for a 200 that carries diffs and no
// prose at all, which is better than a silent warning.
export function reportResult(res,ctx) {
 const warnings = (res?.warnings || []).filter(Boolean).map(String);
 const lines = warnings.length ? warnings : diffTexts(res?.diffs,ctx);
 return {warned:lines.length > 0,lines,tone:diffTone(res?.diffs)};
}

function showDiff(lines,tone = 'none') {
 $('#pDiff').replaceChildren(...lines.map(line => el('p',{},line)));
 $('#pDiff').className = `banner diff-${tone}`;
 $('#pDiff').hidden = false;
 toast(`⚠ ${lines[0]}`,null,null,15000,{warn:true});
}

async function applyNow() {
 if (!state.session?.canWrite || !targets.length) return;
 // A ticked "change owner" with an unreadable id stops here rather than being
 // read as "no owner change" by applyPlan.
 if (paintIdErrors().length) return;
 const valid = sessionGuard();
 const spec = model.spec;
 const plan = applyPlan({
  entries:targets,spec,owner:ownerValue(),group:groupValue(),
  recursive:recursive(),apply:applyMode(),smartX:$('#pSmartX').checked,
  crossMounts:state.session?.family === 'quts_hero',follow:$('#pFollowLinks').checked,
 });
 if (!plan.length) { $('#permsError').textContent = 'Nothing was changed — no permission, owner or group was altered.'; $('#permsError').hidden = false; return; }
 if (recursive() && recursiveSetsSpecial(jobSpecs({spec,apply:applyMode(),smartX:$('#pSmartX').checked}))) {
  $('#permsError').textContent = RECURSIVE_SPECIAL_REFUSAL; $('#permsError').hidden = false; return;
 }
 applying = true; refreshApply();
 $('#permsError').hidden = true; $('#pDiff').hidden = true;
 const ctx = {
  recursive:recursive(),
  protectedPath:targets.some(e => e.class === 'protected' || e.class === 'warn'),
  phrase:targets[0].name,
  group:targets[0].group || '',
 };
 try {
  for (const request of plan) {
   const res = await runMutation(request.endpoint,request.body,(confirm,message) =>
    askPermConfirm(confirm,message,{...ctx,op:request.op}));
   if (!valid()) return;
   if (res === null) return;                       // declined: nothing after it runs either
   if (request.job) { trackJob(res.job); announce(`${request.op === 'chown' ? 'Changing owner' : 'Changing permissions'} — see Operations.`); continue; }
   const {warned,lines,tone} = reportResult(res,{op:request.op,group:ctx.group});
   if (warned) showDiff(lines,tone);
   else announce(request.op === 'chown' ? 'Owner changed.' : 'Permissions changed.');
  }
  loadList(); loadTree();
  if ($('#pDiff').hidden) $('#dlgPerms').close();
 } catch(err) {
  if (!valid()) return;
  $('#permsError').textContent = actionMessage(err); $('#permsError').hidden = false;
  error(new Error(actionMessage(err)));
 } finally { applying = false; if (valid()) refreshApply(); }
}

// openPermsForSelection is what the toolbar, F9 and the context menu call. It
// resolves the explicit selection the same way delete does — fetching pages
// that hold selected rows but were never loaded — so a Shift-range spanning
// unloaded pages is acted on in full or not at all.
export async function openPermsForSelection() {
 if (!listingActions().mutate) return;
 let entries;
 try { entries = await selectionEntries(); } catch(err) { error(err); return; }
 if (entries === null) { error(new Error('Select items individually to change their permissions in this version.')); return; }
 if (!entries.length) { const {entry} = activeSelection(); if (entry) entries = [entry]; }
 if (!entries.length) return;
 openPerms(entries);
}

export function initPerms() {
 // The generation key already makes a stale cache unreachable; dropping it on
 // every session change means it is not merely unreachable but gone.
 subscribe(() => { if (idCache && idCache.generation !== state.sessionGeneration) clearIdCache(); });
 for (const {id,bit} of [...BITS,...SPECIAL_BITS]) {
  $(`#${id}`).addEventListener('change',ev => {
   model = {...model,spec:toggleBit(model.spec,bit,ev.target.checked)};
   repaint();
  });
 }
 $('#pOctal').addEventListener('input',ev => {
  const parsed = parseOctal(ev.target.value);
  if (!parsed) return;                     // half-typed text is not an error yet
  model = {...model,spec:parsed};
  paintGrid(false); paintWarnings();
 });
 $('#pOctal').addEventListener('change',ev => {
  if (ev.target.value.trim() === '') return;     // cleared: back to "mixed"
  if (!parseOctal(ev.target.value)) { $('#permsError').textContent = 'A mode is up to four octal digits, for example 0755.'; $('#permsError').hidden = false; }
 });
 $('#pRecursive').addEventListener('change',() => {
  repaint();
  if (targets.some(isDirectory)) startImpact();
 });
 for (const id of ['pApplyAll','pApplyFiles','pApplyDirs','pSmartX']) $(`#${id}`).addEventListener('change',paintWarnings);
 for (const id of ['pOwnerChange','pGroupChange']) $(`#${id}`).addEventListener('change',() => { ownerEnabled(); paintIdErrors(); });
 for (const id of ['pOwnerId','pGroupId']) $(`#${id}`).addEventListener('input',paintIdErrors);
 $('#pOwner').addEventListener('change',ev => { if (ev.target.value !== '') $('#pOwnerId').value = ev.target.value; });
 $('#pGroup').addEventListener('change',ev => { if (ev.target.value !== '') $('#pGroupId').value = ev.target.value; });
 $('#pRecount').addEventListener('click',() => { if (targets.length) startImpact(); });
 $('#pStopImpact').addEventListener('click',() => { impactRunner.stop(); $('#pImpact').textContent = 'Measurement stopped.'; });
 $('#pApply').addEventListener('click',applyNow);
 // The impact job belongs to the dialog, and ends with it however it ends.
 $('#dlgPerms').addEventListener('close',() => { impactRunner.stop(); targets = []; });
 $('#btnPerms').addEventListener('click',openPermsForSelection);
 $('#propPerms').addEventListener('click',() => { const entry = propsTarget(); if (entry) { $('#dlgProps').close(); openPerms([entry]); } });
 extraActions.push({label:'Permissions…',action:'permissions',run:entry => openPerms([entry])});
}

// setsSpecial and applySpec are re-exported for the dialog's own tests: the
// grid's arithmetic is perm.js's, and nothing here may grow a second copy.
export {setsSpecial,applySpec,octal};
