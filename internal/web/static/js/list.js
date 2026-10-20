import {api} from './api.js';
import {$,el,error,pathArgs,route,heightRule,placeRule,menuPlacement,announce,applyWhy} from './dom.js';
import {state,update,selected,countSelected,subscribe,sessionGuard,listingActions} from './state.js';
import {nameCell,isDirectory,isReadable,isSymlink,hasTarget,fileTarget,actionHint,directoryNotice} from './badges.js';
import {whyDisabled,entryKind,MAX_ROOTS,tooManySentence} from './why.js';
import {emptyState} from './empty.js';
import {syncOverflow} from './narrow.js';
import {view,download,downloadMode,downloadArchive} from './viewer.js';
import {properties} from './props.js';
import {formatBytes} from './jobs.js';
// pathBytes is the byte spelling of a path reference. It lives in transfer.js
// because that is where the rule was first needed (a destination that IS one of
// the copied items), and there must be exactly one of it: two implementations
// of "are these the same file" is how the lookalike bug gets reintroduced.
import {pathBytes} from './transfer.js';
// DEFAULT_PAGE is what the first request asks for (stabilization contract §3.2).
// A folder of up to 2,000 entries then arrives in ONE response — one reading of
// the directory, which is what select-all needs to be able to say "everything"
// (§3.3). The server may answer with a smaller page (its listMax), and a larger
// folder pages lazily; either way the page size is the one the server answered
// with, never assumed.
export const DEFAULT_PAGE = 2000;
let pageSize = DEFAULT_PAGE;
let topHeight,bottomHeight;
// placeMenu moves the context menu through its CSSOM rule (§3.7); a no-op until
// initList has inserted the rule.
let placeMenu = () => {};
const pending = new Map();
let typeAhead = '', typedAt = 0;
const rowHeight = () => matchMedia('(max-width:30rem)').matches ? 44 : 36;
export const entryAt = index => state.pages.get(Math.floor(index/pageSize))?.[index%pageSize];
export const focused = () => entryAt(state.focus);
// selectedOne resolves the single SELECTED entry, or null when the selection is
// not exactly one item, or when focus has moved off the selected row (Ctrl+Arrow
// moves focus without changing the selection). Rename and Properties act on this,
// never on focused() alone, so a toolbar action cannot target a focused-but-
// unselected entry (standard P2 / round-3 finding 7). What it hands back is the
// entry the row showed when it was selected (stabilization contract §3.1).
export const selectedOne = () => {
 const e = focused();
 if (countSelected() !== 1 || !e || !selected(state.focus)) return null;
 return state.selection.get?.(state.focus) || e;
};
// extraActions lets other modules (actions.js) contribute context-menu items
// without list.js importing them, which would create a cycle. Each is
// {label, run(entry), show?(entry), disabled?(entry)}.
export const extraActions = [];
// selectionEntries resolves the selection to what an action may act on
// (stabilization contract §3.1, §3.4): the entries the selected rows SHOWED, in
// listing order, with no hidden row among them and no file twice — or a clear
// Error, never a truncated set. Delete, Copy, Move, Permissions and the archive
// download all come through here.
//
// More than MAX_ROOTS is refused first, in the reason table's own sentence and
// before anything is fetched (§3.5). The toolbar has already said so by then;
// this is what keeps the keyboard — Delete, Ctrl+C, F9 — from being a way round
// it, because the server refuses the request either way.
//
// A row a Shift range chose before its page arrived has no entry yet. A
// directory larger than 2,000 entries loads lazily, and the old synchronous
// selectedEntries silently dropped such rows, so a delete of such a selection
// removed only the loaded subset while reporting success (standard P2). Their
// pages are fetched now and each row is judged on arrival — kept with the entry
// it brought, or dropped if the filter or the /share rule hides it — and a row
// whose page still cannot supply it makes the whole call refuse.
export async function selectionEntries() {
 const count=countSelected();
 if (count>MAX_ROOTS) throw new Error(tooManySentence(count));
 // The selection as it stood when the action was asked for. Fetching pages
 // takes time, and a click made meanwhile is a new selection for the NEXT
 // action, not a silent change to this one.
 const asked=state.selection,generation=state.generation;
 const needed=new Set();
 for (const [index,entry] of selectionPairs(asked)) if (!entry && !entryAt(index)) needed.add(Math.floor(index/pageSize));
 for (const n of needed) {
  await page(n,generation);
  if (generation!==state.generation || !state.session) throw new Error('The listing changed while preparing the selection. Try again.');
 }
 // The live selection is kept honest as well: rows whose pages are here now
 // take their entries, and a row hidden since it was chosen leaves it — on the
 // rows and in the status bar's count, not only in state.
 const live=pruneSelection(settleSelection(state.selection,state.pages,pageSize,navigable) || state.selection,navigable);
 if (live!==state.selection) { update({selection:live}); render(); }
 const entries=resolveSelection(settleSelection(asked,state.pages,pageSize,navigable) || asked,navigable);
 if (!entries) throw new Error('Some selected items are still loading. Scroll through the selection to load them, or select fewer items, then try again.');
 if (entries.length>MAX_ROOTS) throw new Error(tooManySentence(entries.length));
 return entries;
}
// matchesFilter is the quick filter's rule, in ONE place. navigable() and
// render() both decide what a row does by this test, and so must anything that
// reasons about whether a row can be SEEN (revealFilter, below) — two spellings
// of the same predicate is how they drift apart.
export const matchesFilter = (filter,name) =>
 !filter || String(name ?? '').toLocaleLowerCase().includes(String(filter).toLocaleLowerCase());
// rowVisible is whether a row can be SEEN: matched by the name filter when
// there is one, and not a volume root at /share — the listing hides those and
// the mount links stand for them. It is the test the selection invariant is
// stated in (stabilization contract §3.1); navigable is it over the current
// state, and is what every keyboard move, the focus repair and the selection
// itself ask.
export const rowVisible = (entry,filter,path) => !!entry && !(entry.volumeRoot && path==='/share') && matchesFilter(filter,entry.name);
export const navigable = e => rowVisible(e,state.filter,state.path);

// --- the selection, as data (stabilization contract §3) -----------------------
//
// The selection is a Map from listing index to the entry that row showed (see
// state.js). The functions below are pure over it, so every rule the contract
// states — what joins, what leaves, what an action receives — is a unit test.

// selectionPairs is the selection as [index, entry] pairs in listing order. A
// Set of indices — the selection's shape before §3.1, and what an older caller
// or test may still hand in — reads as rows whose entries are not known yet,
// which is the honest reading of an index on its own.
export function selectionPairs(selection) {
 const pairs = selection instanceof Map ? [...selection] : [...(selection || [])].map(index => [index,null]);
 return pairs.sort((a,b) => a[0]-b[0]);
}

// settleSelection gives the rows chosen before their page arrived the entry
// the page brought — or takes them out, when it is an entry the user cannot see
// (§3.1): the moment a row can be judged is the moment it is. Pure over the
// selection, the pages, the page size and the visibility test; null when there
// was nothing to settle, so the caller can skip a repaint.
export function settleSelection(selection,pages,size,visible) {
 let next = null;
 for (const [index,entry] of selectionPairs(selection)) {
  if (entry) continue;
  const found = pages?.get(Math.floor(index/size))?.[index%size];
  if (!found) continue;
  next ??= new Map(selectionPairs(selection));
  if (visible(found)) next.set(index,found); else next.delete(index);
 }
 return next;
}

// pruneSelection drops the rows a change of view has hidden (§3.4): a filter
// typed, or a stashed selection coming back under a filter that has changed
// since. A row still waiting for its page is kept — nothing is known about it
// yet, and its page settles it. Hands back the SAME selection when nothing was
// hidden, so "did anything change" is an identity test.
export function pruneSelection(selection,visible) {
 const pairs = selectionPairs(selection);
 const kept = pairs.filter(([,entry]) => !entry || visible(entry));
 return kept.length === pairs.length && selection instanceof Map ? selection : new Map(kept);
}

// resolveSelection is what an action receives: the selected entries in listing
// order, each the entry its row SHOWED (§3.1), no hidden row among them, and no
// file twice (§3.4). Two indices can name one file — the folder changed between
// two page reads, so the entry last on one page is first on the next — and an
// action handed a path twice deletes it, copies it or counts it twice. The test
// is in bytes, the only spelling two paths can honestly be compared in, and a
// reference whose bytes cannot be determined is never called a duplicate of
// anything. null when a row has no entry yet: the caller refuses rather than act
// on part of a selection.
export function resolveSelection(selection,visible) {
 const out = [],seen = new Set();
 for (const [,entry] of selectionPairs(selection)) {
  if (!entry) return null;
  if (!visible(entry)) continue;
  const bytes = pathBytes(entry);
  if (bytes) {
   if (seen.has(bytes)) continue;
   seen.add(bytes);
  }
  out.push(entry);
 }
 return out;
}

// selectAllPlan is Ctrl+A, decided (stabilization contract §3.3). It selects
// every row the user can see — all of them, or with a filter set the ones that
// match — and only when two things hold. The listing came in ONE response: a
// folder read in several requests is several readings of a directory that may
// have changed in between, and "everything" over that is a claim nobody
// checked. And the count is within MAX_ROOTS: a selection no action can carry
// is not one worth making. Otherwise it selects nothing and returns the
// sentence that says why, with the number in it.
//
// This replaces the select-all ("exclude") mode, which selected "everything
// except these" over rows nobody had loaded; every action refused it, so Ctrl+A
// followed by Delete said "Select items individually…" — the reproduced bug.
export function selectAllPlan({pages,total = 0,loading = false,filter = '',path = ''} = {}) {
 const count = value => Number(value || 0).toLocaleString();
 if (loading) return {sentence:'This folder is still loading, so nothing was selected.'};
 const first = pages?.get(0);
 if (!Array.isArray(first)) return {sentence:'Nothing is listed here, so nothing was selected.'};
 if (pages.size !== 1 || first.length !== total) {
  let loaded = 0;
  for (const entries of pages.values()) loaded += entries?.length || 0;
  const detail = pages.size === 1 ? `only its first ${count(first.length)} entries are loaded`
   : loaded < total ? `only ${count(loaded)} of its ${count(total)} entries are loaded`
   : `its ${count(total)} entries were listed in more than one response`;
  return {sentence:`This folder is too large to select all at once (${detail}).`};
 }
 const selection = new Map();
 first.forEach((entry,index) => { if (rowVisible(entry,filter,path)) selection.set(index,entry); });
 if (selection.size > MAX_ROOTS) {
  const limit = `select-all works on up to ${MAX_ROOTS.toLocaleString()} at a time`;
  return {sentence:filter
   ? `${count(selection.size)} items match the filter; ${limit}. Narrow the filter or select a range.`
   : `This folder has ${count(selection.size)} items; ${limit}. Filter the names or select a range.`};
 }
 return {selection};
}

// sizeCell and dateCell are what a row's Size and Modified cells say
// (stabilization contract §3.6): the size in units and the date in its short
// form, each with the exact value as the cell's title — nothing the column used
// to show is lost, it is one hover away. A folder's size is "—": the number a
// directory carries is its inode's, not what is in it. Pure, so the wording is
// a unit test.
export function sizeCell(entry) {
 const bytes = Number(entry?.size);
 if (!entry || isDirectory(entry) || !Number.isFinite(bytes) || bytes < 0) return {text:'—',title:''};
 return {text:formatBytes(bytes),title:`${bytes.toLocaleString()} bytes`};
}
export function dateCell(mtime) {
 const date = mtime === undefined || mtime === null || mtime === '' ? null : new Date(mtime);
 if (!date || !Number.isFinite(date.getTime())) return {text:'—',title:''};
 const [short,full] = dateFormats();
 return {text:short(date),title:full(date)};
}

// dateFormats is the two date forms as formatters made ONCE, on the first row
// that needs them, and kept (Astra r1 P2). Date#toLocaleString with options
// builds a new Intl.DateTimeFormat on every call, and render() formats every
// loaded row on each scroll and each filter keystroke — up to 2,000 rows, which
// measured about 170 ms of formatting per repaint against a few milliseconds
// for formatters reused. The page's locale does not change under it.
//
// The title's options are exactly what Date#toLocaleString() fills in when it
// is given none — year, month, day, hour, minute and second, all numeric — so
// the title reads as the whole column did before §3.6.
let shortDate = null,fullDate = null;
function dateFormats() {
 if (!shortDate) {
  shortDate = new Intl.DateTimeFormat(undefined,{dateStyle:'short',timeStyle:'short'}).format;
  fullDate = new Intl.DateTimeFormat(undefined,{year:'numeric',month:'numeric',day:'numeric',hour:'numeric',minute:'numeric',second:'numeric'}).format;
 }
 return [shortDate,fullDate];
}

function query(offset) { return {...pathArgs(state),offset,limit:pageSize,sort:state.sort,desc:state.desc,hidden:state.hidden,volumes:false}; }

async function page(number,generation) {
 const valid=sessionGuard();
 if (state.pages.has(number)) return;
 const key = `${state.sessionGeneration}:${generation}:${number}`;
 if (pending.has(key)) return pending.get(key);
 const request = (async () => {
  const data = await api('api/fs/list',query(number*pageSize));
  if (!valid() || generation !== state.generation || !state.session) return;
  if (!Number.isInteger(data.limit) || data.limit < 1) throw new Error('Invalid listing page size.');
  if (number === 0) pageSize = data.limit;
  else if (data.limit !== pageSize) throw new Error('Listing page size changed. Refresh to continue.');
  const pages = new Map(state.pages); pages.set(number,Array.isArray(data.entries) ? data.entries : []);
  // The folder's display class travels with its first page and is kept: it is
  // what the shield badge and the path notice are painted from (badges.js). It
  // is a lexical hint, NOT the guard's verdict on an operation, so it is not
  // what the reason table's `guard` cause is read from — see whyContext
  // (Astra r1 #6).
  const patch = number === 0 ? {pages,total:data.total,loading:false,dirClass:data.class || ''} : {pages,total:data.total,loading:false};
  // Rows a Shift range chose before this page arrived are judged now that they
  // can be: kept with the entries the page brought, or dropped where the filter
  // or the /share rule hides them (stabilization contract §3.1).
  const settled = settleSelection(state.selection,pages,pageSize,navigable);
  if (settled) patch.selection = settled;
  update(patch);
  if (number === 0) directoryNotice(data);
  render();
 })();
 pending.set(key,request);
 try { await request; } catch(err) { if (valid() && generation===state.generation) throw err; } finally { pending.delete(key); }
}

export async function loadList() {
 if (!state.session) return;
 const valid=sessionGuard();
 const generation = state.generation+1;
 pageSize = DEFAULT_PAGE;
 update({generation,pages:new Map(),total:0,selection:new Map(),focus:0,anchor:0,loading:true,listError:null,dirClass:''});
 $('#listViewport').scrollTop = 0; $('#status').textContent = 'Loading…'; render();
 try {
  await page(0,generation);
  if (!valid() || generation !== state.generation) return;
  if (state.total <= 2000) for (let n=1;valid() && generation===state.generation && n<Math.ceil(state.total/pageSize);n++) await page(n,generation);
  if (valid() && generation===state.generation) render();
  // A search result asked for one of these entries to be revealed. The request
  // is consumed exactly once, whether or not it can be honoured: a stale one
  // must never fire against a folder the user has since navigated to by hand.
  // revealApplies decides whether THIS listing is the one it asked for; when it
  // is not, the user went somewhere else and the request dies quietly with the
  // navigation that made it.
  if (valid() && generation===state.generation && state.pendingReveal) {
   const want=state.pendingReveal;
   update({pendingReveal:null});
   if (revealApplies(want,{path:state.path,pathB64:state.pathB64},generation) && !revealEntry(want)) {
    announce(`Opened this folder — “${want.name}” is not on the pages loaded so far.`);
   }
  }
 } catch(err) {
  if (valid() && generation === state.generation) {
   // The failure is KEPT, not just reported: an empty list and a list the
   // kernel refused must not look the same (§8.1). The status bar still says
   // what happened; the list region now says it too, where the rows would be.
   update({loading:false,pendingReveal:null,listError:{code:err.code || '',message:err.message || ''}});
   render();
   error(err);
   describeRefusal(err,generation,valid);
  }
 }
}

// describeRefusal asks the kernel for the folder's own owner and mode so the
// refused-listing sentence can NAME them (§8.1: the kernel's verdict, reported
// — INV-2). Reading a directory and traversing to it are different permissions,
// so a stat usually survives a listing that did not; when it does not, the
// sentence falls back to the server's own message and says nothing it does not
// know.
async function describeRefusal(err,generation,valid) {
 if (!['permission','protected','readonly','read_only'].includes(String(err.code || ''))) return;
 try {
  const entry = await api('api/fs/stat',pathArgs(state));
  if (!valid() || generation !== state.generation || !state.listError) return;
  update({listError:{...state.listError,owner:entry.user || (entry.uid != null ? `uid ${entry.uid}` : ''),mode:entry.modeStr || entry.mode || ''}});
  render();
 } catch { /* The stat was refused too; the sentence stays as it is. */ }
}

// select applies one click or key to the selection (stabilization contract
// §3.4). A row joins only if the user can see it, and it joins WITH the entry it
// shows, so what an action later acts on is what was on the screen (§3.1). A
// Shift range adds the visible rows between the anchor and the target and skips
// the ones the filter or the /share rule hides: it used to take every index in
// between, so a row filtered out of sight rode along into the next Delete.
//
// A row whose page has not arrived is not yet known to be anything, and it is
// held pending — index now, entry when its page lands (page() and
// selectionEntries settle it). The row a click or a key is aimed at is always
// held so, because move() loads its page at once. The other rows of a Shift
// range are held so only while no filter is set: every one of them will be
// shown when its page lands. With a filter set, a row whose name has not been
// read cannot be shown to match — the filter works on loaded names only, and
// the status bar says so — so the range takes the loaded rows that match.
function select(index,event={}) {
 const set = new Map(selectionPairs(state.selection));
 const admit = (i,unloaded) => {
  const entry = entryAt(i);
  if (entry) { if (navigable(entry)) set.set(i,entry); }
  else if (unloaded && i >= 0 && i < state.total) set.set(i,null);
 };
 if (event.shiftKey) {
  const a = Math.min(state.anchor,index), b = Math.max(state.anchor,index);
  // Range selection stores what it can see; it never fetches the whole directory.
  for (let i=a;i<=b;i++) admit(i,i === index || !state.filter);
 } else if (event.ctrlKey || event.metaKey || event.toggle) {
  if (set.has(index)) set.delete(index); else admit(index,true);
 } else { set.clear(); admit(index,true); }
 update({selection:set,focus:index,anchor:event.shiftKey ? state.anchor : index});
 syncSelection();
}

// selectAll is Ctrl+A: selectAllPlan's verdict, applied — or, when it refuses,
// said in its one sentence on the status bar and to a screen reader, with the
// selection left exactly as it was (stabilization contract §3.3).
function selectAll() {
 const plan = selectAllPlan({pages:state.pages,total:state.total,loading:state.loading,filter:state.filter,path:state.path});
 if (!plan.selection) { $('#status').textContent = plan.sentence; announce(plan.sentence); return; }
 update({selection:plan.selection});
 syncSelection();
}

// filterTo applies the quick filter, and the invariant with it (stabilization
// contract §3.1, §3.4): a selected row the new filter hides leaves the selection
// as it leaves the screen, instead of staying selected out of sight for the next
// Delete to find. The user who had it selected is told; with nothing selected
// there is nothing to tell.
function filterTo(text) {
 const filter = String(text ?? '');
 const before = state.selection;
 const after = pruneSelection(before,e => rowVisible(e,filter,state.path));
 update(after === before ? {filter} : {filter,selection:after});
 const dropped = before.size-after.size;
 if (dropped > 0) announce(`${dropped.toLocaleString()} selected item${dropped === 1 ? ' is' : 's are'} hidden by the filter and no longer selected.`);
 render();
}

function syncSelection() {
 // Keep click targets alive so the browser can dispatch a desktop double-click.
 let hasFocusRow = false;
 for (const row of $('#listRows').querySelectorAll('[data-idx]')) {
  const index = Number(row.dataset.idx), active = index === state.focus && navigable(entryAt(index));
  const isSelected = selected(index);
  row.classList.toggle('selected',isSelected);
  row.setAttribute('aria-selected',String(isSelected));
  row.tabIndex = active ? 0 : -1;
  if (active) hasFocusRow = true;
 }
 $('#list').tabIndex = hasFocusRow ? -1 : 0;
 if (!state.loading && state.session) status();
}

function status() {
 const n = countSelected();
 const mode = state.session?.canWrite ? 'read-write' : 'read-only browse';
 // While the results cover the listing, the listing's count is not what the
 // status bar should be reading out: "2 of 5 selected" next to a pane showing
 // search hits describes something the user cannot see.
 const where = listingActions().listing
  ? `${n.toLocaleString()} of ${state.total.toLocaleString()} selected · ${state.path}`
  : `Search results · ${(state.searchResults?.hits?.length || 0).toLocaleString()} found · listing paused at ${state.path}`;
 $('#status').textContent = `${where} · ${state.session?.family || ''} · ${mode}${state.filter ? ' · Filtering loaded names only' : ''}`;
 refreshToolbar();
}

// activeSelection is what the toolbar and every single-item action look at. It
// is the LISTING's selection while the listing is on screen; while the search
// results have replaced it, it is the focused RESULT and nothing else — the
// listing's selection is invisible then, and acting on invisible rows is the
// bug the gate exists to prevent (round 1, finding 1).
export function activeSelection() {
 const gate = listingActions();
 if (!gate.listing) {
  const found = state.searchResults,hit = found?.hits?.[found?.focus] ?? null;
  return {gate,count:hit ? 1 : 0,entry:hit,one:!!hit};
 }
 const e = focused(),one = gate.count === 1 && !!e && selected(state.focus);
 // One selected row is acted on as the entry it showed (§3.1); with nothing
 // selected, the focused row is still what the single-item reads point at.
 return {gate,count:gate.count,entry:one ? state.selection.get?.(state.focus) || e : e,one};
}

// whyContext is the state every control's verdict is read from, assembled once.
//
// It is exported because the context menu, the dialogs and the tests all have
// to ask the SAME question the toolbar asks: one table (why.js), one context,
// and no third place quietly deciding that a button should be grey.
// kindOf is the one word why.js needs for "is this the right sort of thing".
//
// An unresolved symlink is reported differently in the two views, and only the
// context knows which it is. The listing follows symlinks, so an unresolved one
// there really is broken; a search hit was never followed, so calling it broken
// states something nobody checked (round 10).
export function kindOf(entry,listing = true) {
 if (!entry) return '';
 const broken = isSymlink(entry) && !hasTarget(entry);
 if (broken && !listing) return 'unfollowed';
 return entryKind({dir:isDirectory(entry),readable:isReadable(entry),broken});
}

export function whyContext(extra = {}) {
 const {gate,count,entry,one} = activeSelection();
 // The kind only means anything for a single selection: it answers "is this the
 // right sort of thing", which is not a question about twelve items.
 const kind = one && entry ? kindOf(entry,gate.listing) : '';
 return {
  readOnly:!state.session?.canWrite,
  // The listing is not on screen: a selection-class reason with its own
  // sentence, never reported as read-only mode (round 1, finding 1).
  paused:!gate.listing,
  count,one,kind,
  entry:one ? entry : null,
  session:state.session,
  // The guard cause waits for the guard's OWN verdict, and the listing does not
  // carry one (Astra r1 #6). `state.dirClass` is browse.go's `class` — a
  // LEXICAL display hint ("Display hints only", browse.go) that calls everything
  // under /etc, /usr, /var, /root and the rest 'protected', which is the badge
  // and the path notice badges.js paints. It is not an operation verdict: the
  // guard refuses SPECIFIC operations in those regions and permits the rest, and
  // reading it as a blanket denial disabled the repair work an administrator
  // signs in to do. So nothing is denied here; the server says no where it means
  // it, in its own words, and the class stays advisory. When the listing one day
  // reports the guard's verdict per operation, that field — not the class — is
  // what belongs in this line.
  guard:{denied:false},
  ...extra,
 };
}

// refreshToolbar reflects the current selection and the session's write
// capability onto every action button, through the ONE reason table (M4
// contract §7). Mutating buttons are disabled (never hidden) and carry the
// verdict's sentence as a title, as aria-disabled and as an aria-describedby
// node, per the safety plan §3.2/§4.1.
export function refreshToolbar() {
 const {count:n,entry:e,one} = activeSelection();
 const ctx = whyContext();
 // The Download button is a SPLIT (contract §2.4): one readable file leaves as
 // itself, anything else — a folder, or several items — leaves as a ZIP, and
 // the ▾ menu offers tar.gz instead. The button says which it will do, so the
 // click is never a surprise.
 const mode = downloadMode({count:n,entry:one ? e : null});
 const download = whyDisabled('download',ctx);
 // The archive wording replaces the title only when the button can be pressed:
 // a selection past MAX_ROOTS is an archive that will not be made, and its
 // button must say why rather than what it would have done (§3.5).
 applyWhy('#btnDownload',mode === 'archive' && download.allowed ? {...download,sentence:'Download the selection as a ZIP archive'} : download);
 $('#btnDownload').textContent = mode === 'archive' ? 'Download as ZIP' : 'Download';
 applyWhy('#btnDownloadAs',download);
 applyWhy('#btnView',whyDisabled('viewText',ctx));
 applyWhy('#btnProps',whyDisabled('properties',ctx));
 applyWhy('#btnMkdir',whyDisabled('newFolder',ctx));
 applyWhy('#btnUpload',whyDisabled('upload',ctx));
 // Searching is reading: it needs a session, never write permission.
 applyWhy('#btnSearch',whyDisabled('search',ctx));
 // Permissions acts on the WHOLE selection — a recursive chmod over several
 // roots is one job — so it needs a selection and write permission, and never
 // the owner arithmetic: that is a hint the table returns as `capability`,
 // which explains without locking (PLAN decision 12, M3 contract §5.2).
 applyWhy('#btnPerms',whyDisabled('permissions',ctx));
 applyWhy('#btnRename',whyDisabled('rename',ctx));
 applyWhy('#btnDelete',whyDisabled('delete',ctx));
 applyWhy('#btnCopy',whyDisabled('copy',ctx));
 applyWhy('#btnMove',whyDisabled('move',ctx));
 // The ⋯ menu mirrors whatever the buttons have just been told, so the narrow
 // layout can never disagree with the wide one (§9.5).
 syncOverflow();
 paintEmpty();
}

// --- the empty states (§8) ---------------------------------------------------

// loadedCount and loadedMatches are counted rather than estimated, because
// "4,182 entries are loaded" is the sentence's whole point: a number is what
// distinguishes "nothing is there" from "we stopped looking". Both walk only
// the pages actually held, and the matcher runs only when a filter is set.
function loadedCount() { let n = 0; for (const entries of state.pages.values()) n += entries.length; return n; }
function loadedMatches() {
 let n = 0;
 for (const entries of state.pages.values()) for (const entry of entries) if (matchesFilter(state.filter,entry.name)) n++;
 return n;
}

let emptyAction = '';
// paintEmpty renders the list region's empty state. An empty folder and a
// folder you cannot read must never look the same (§8.1).
export function paintEmpty() {
 const box = $('#listEmpty');
 if (!box) return null;
 const info = emptyState('list',{
  loading:state.loading,
  total:state.total,
  loaded:loadedCount(),
  filter:state.filter,
  matches:state.filter ? loadedMatches() : 0,
  error:state.listError,
  owner:state.listError?.owner || '',
  mode:state.listError?.mode || '',
  // The offer goes through the SAME table as the button it presses (§8.1's
  // "one action", §7.1's one reason table): read-only, a paused listing and a
  // guard-denied folder each withdraw it, rather than offering a control that
  // forwards to a disabled button or to a 403 (round 2, finding 2).
  canCreate:whyDisabled('newFolder',whyContext()).allowed,
 });
 box.hidden = !info;
 emptyAction = info?.action?.id || '';
 if (!info) return null;
 $('#listEmptyText').textContent = info.sentence;
 $('#listEmptyDetail').textContent = info.detail;
 $('#listEmptyDetail').hidden = !info.detail;
 const action = $('#listEmptyAction');
 action.hidden = !info.action;
 if (info.action) action.textContent = info.action.label;
 // The refused state is marked in WORDS by the sentence itself; the class only
 // carries the border, so nothing here is signalled by colour alone (§4.1).
 box.classList?.toggle('refused',info.state === 'listing-refused' || info.state === 'listing-failed');
 return info;
}

export function render() {
 if (!topHeight) return;
 const viewport = $('#listViewport'), h = rowHeight(), virtual = state.total > 2000;
 $('#list').classList.toggle('virtual',virtual);
 const start = virtual ? Math.max(0,Math.floor(viewport.scrollTop/h)-8) : 0;
 const end = virtual ? Math.min(state.total,start+Math.ceil(viewport.clientHeight/h)+20) : state.total;
 const hadFocus = $('#listRows').contains(document.activeElement);
 if (focused() && !navigable(focused())) {
  for (let i=start;i<end;i++) if (navigable(entryAt(i))) { update({focus:i}); break; }
 }
 topHeight(start*h); bottomHeight(Math.max(0,state.total-end)*h);
 $('#list').setAttribute('aria-rowcount',String(state.total+1));
 $('#list').setAttribute('aria-busy',String(state.loading));
 const rows = [];
 const needed = new Set();
 for (let i=start;i<end;i++) {
  const e = entryAt(i);
  if (!e) { needed.add(Math.floor(i/pageSize)); rows.push(el('div',{class:'fileRow','aria-hidden':'true'},'Loading…')); continue; }
  // Preserve virtual row geometry even while filtering the loaded page.
  const match = matchesFilter(state.filter,e.name);
  const row = el('div',{id:`row-${i}`,role:'row',class:`fileRow ${e.class || ''}${match ? '' : ' filtered'}${e.volumeRoot && state.path==='/share' ? ' volumeRow' : ''}${!isDirectory(e) && !isReadable(e) ? ' special' : ''}`,tabindex:i===state.focus ? '0' : '-1','aria-rowindex':i+2,'aria-selected':selected(i),'data-name':e.name,'data-kind':e.type,'data-idx':i});
  // Size and Modified read like a file manager's, with the exact value one
  // hover away (§3.6); a cell with nothing more to say carries no title.
  const size = sizeCell(e),when = dateCell(e.mtime);
  row.append(nameCell(e),
   el('span',size.title ? {role:'gridcell',title:size.title} : {role:'gridcell'},size.text),
   el('span',{role:'gridcell',class:'extra'},e.type),
   el('span',when.title ? {role:'gridcell',title:when.title} : {role:'gridcell'},when.text),
   el('span',{role:'gridcell',class:'extra'},e.modeStr || e.mode),el('span',{role:'gridcell',class:'extra'},`${e.user || e.uid}:${e.group || e.gid}`));
  row.addEventListener('click',ev => { select(i,ev); focusRow(); if (matchMedia('(max-width:30rem)').matches && !ev.ctrlKey && !ev.shiftKey) open(e); });
  row.addEventListener('dblclick',() => open(e));
  // The anchor is read BEFORE the selection changes: selecting relabels the
  // toolbar (Download ↔ Download as ZIP), which can rewrap it and move every
  // row, and the pointer must be judged against the row it was over.
  row.addEventListener('contextmenu',ev => { ev.preventDefault(); const at = pointerAnchor(ev,row); select(i); contextMenu(e,at); });
  row.addEventListener('focus',() => { if (state.focus !== i) { update({focus:i}); syncSelection(); } });
  rows.push(row);
 }
 $('#listRows').replaceChildren(...rows);
 syncSelection();
 paintEmpty();
 if (hadFocus) focusRow();
 const valid=sessionGuard(),generation=state.generation;
 for (const n of needed) page(n,generation).catch(err => { if (valid() && generation===state.generation) error(err); });
}

function focusRow() { document.getElementById(`row-${state.focus}`)?.focus({preventScroll:true}); }
export function open(e) {
 if (!e) return;
 if (isDirectory(e)) { location.hash = route(e); $('#tree').classList.remove('open'); $('#btnTree').setAttribute('aria-expanded','false'); }
 else view(e);
}
async function move(index,event) {
 const valid=sessionGuard(),generation=state.generation;
 index = Math.max(0,Math.min(state.total-1,index));
 if (state.total === 0) return;
 const direction = index < state.focus ? -1 : 1;
 while (entryAt(index) && !navigable(entryAt(index))) {
  index += direction;
  if (index < 0 || index >= state.total) return;
 }
 if (event.ctrlKey || event.metaKey) update({focus:index}); else select(index,event);
 const v = $('#listViewport'),h = rowHeight(), previousScroll = v.scrollTop;
 if (index*h < v.scrollTop) v.scrollTop = index*h;
 if ((index+1)*h > v.scrollTop+v.clientHeight) v.scrollTop = (index+1)*h-v.clientHeight;
 try { await page(Math.floor(index/pageSize),generation); }
 catch(err) { if (valid() && generation===state.generation) error(err); return; }
 if (valid() && generation===state.generation) {
  if (v.scrollTop !== previousScroll) render(); else syncSelection();
  focusRow();
 }
}

// archiveOptions is the one place the crossing question is answered for an
// archive. There is no dialog to carry a checkbox — the browser owns the
// download — so the hero default the delete and transfer dialogs both open with
// (include mounted sub-folders) is the default here too: on QuTS hero a share's
// sub-datasets look like ordinary folders, and an archive that silently omitted
// them would be wrong in a way nobody could see until they opened it.
function archiveOptions() { return {crossMounts:state.session?.family === 'quts_hero'}; }

// revealIndex finds the wanted entry among the pages that are LOADED, in the
// only spelling two paths can honestly be compared in: BYTES.
//
// It used to compare pathB64 when both sides had one and fall back to the
// displayed NAME when either did not — and a name is a lossy view. A directory
// holding a file called "\xff" and another literally called "�" shows the same
// text for both; where only one of them carried authoritative bytes, the
// comparison matched whichever came first, and the rename or delete the user
// then performed on the "revealed" row acted on the other file (round 2,
// finding 1). pathBytes settles it: a reference with pathB64 decodes to the
// filesystem's own bytes, one without is UTF-8 by construction, and a
// reference whose bytes cannot be determined matches NOTHING rather than
// matching by resemblance.
//
// Pure — pages, page size and the wanted reference in, an index or -1 out — so
// the lookalike case is a unit test rather than a story about a NAS.
export function revealIndex(pages,size,want) {
 const wanted = pathBytes(want);
 if (!wanted) return -1;
 for (const [p,entries] of pages || []) {
  const n = (entries || []).findIndex(e => { const bytes = pathBytes(e); return !!bytes && bytes === wanted; });
  if (n >= 0) return p*size+n;
 }
 return -1;
}

// revealApplies says whether a pending reveal belongs to the listing that has
// just loaded. A reveal is a request made by ONE navigation, about ONE folder,
// and it must die with that navigation.
//
// Without the binding it was satisfied by whatever loaded next: click a hit at
// /a/report.txt, change your mind and go to /b before /a answers, and /b's
// listing consumed the request and selected /b/report.txt — a different file,
// now sitting under the cursor for a rename or a delete (round 2, finding 4).
//
// Two conditions, and both are necessary. The loaded folder must BE the hit's
// parent, compared in bytes like every other path comparison. And the load must
// have STARTED after the request: a listing already in flight when the hit was
// clicked describes the folder the user is leaving, not the one they asked for.
//
// Pure, so both races are unit tests rather than timing stories.
export function revealApplies(pending,folder,generation) {
 if (!pending) return false;
 const requested = Number(pending.generation);
 if (Number.isFinite(requested) && !(Number(generation) > requested)) return false;
 const want = pathBytes({path:pending.parent,pathB64:pending.parentB64});
 const here = pathBytes(folder);
 return !!want && !!here && want === here;
}

// revealFilter decides what the quick filter must do so that a revealed row is
// actually VISIBLE.
//
// The filter hides every loaded row it does not match (.filtered, display:none),
// and render() moves focus off a row that is hidden. Revealing a search hit
// through a filter therefore selected a row nobody could see, left the focus
// somewhere else entirely, and a Delete or a Copy to… then acted on that
// invisible selection (round 4, finding 1).
//
// It clears the filter only when the filter is what would hide the hit: a
// filter the hit matches is doing no harm, and silently discarding the user's
// own typing when it was not in the way would be its own small rudeness.
//
// Pure, so "would this row have been visible" is a unit test.
export function revealFilter(filter,entry) {
 const text = String(filter ?? '');
 if (!text) return {clear:false,note:''};
 const name = String(entry?.name ?? '');
 if (matchesFilter(text,name)) return {clear:false,note:''};
 return {clear:true,note:`Name filter “${text}” cleared to show “${name}”.`};
}

// revealEntry selects and focuses the wanted entry and says whether it found
// it. A folder past 2,000 entries loads lazily, so a hit can legitimately be on
// a page nobody has fetched; that is a "no", never a silent nothing.
export function revealEntry(want) {
 if (!want) return false;
 const index = revealIndex(state.pages,pageSize,want);
 if (index < 0) return false;
 // One update, so the filter and the selection land in the same repaint: two
 // would render once with the row still hidden.
 const entry = entryAt(index);
 const {clear,note} = revealFilter(state.filter,entry);
 // The filter is not the only thing that hides a row: /share does not list its
 // volume roots (the mount links stand for them). A hit on one is found but not
 // selected, because a selection never holds a row nobody can see (stabilization
 // contract §3.1) — and it is said, so the reveal is not a silent nothing. True,
 // because the request has been answered: there is nothing more to look for.
 if (!rowVisible(entry,clear ? '' : state.filter,state.path)) {
  announce(`“${entry.name}” is a storage volume, which this folder does not list, so it was not selected.`);
  return true;
 }
 const patch = {selection:new Map([[index,entry]]),focus:index,anchor:index};
 if (clear) { $('#searchBox').value = ''; patch.filter = ''; }
 update(patch);
 const viewport = $('#listViewport'),h = rowHeight();
 viewport.scrollTop = Math.max(0,index*h-Math.floor(viewport.clientHeight/2));
 render(); focusRow();
 if (clear) announce(note);
 return true;
}

// downloadSelection streams the whole explicit selection as one archive. It
// resolves the selection the way every multi-item action does — fetching pages
// a Shift-range spans that were never loaded — so an archive is built from the
// selection in full or not at all, never from the loaded subset (standard P2),
// and never from more than MAX_ROOTS items (stabilization contract §3.5).
export async function downloadSelection(format) {
 // While the results cover the listing there is no listing selection to
 // resolve: the archive is of the focused hit, the one item on screen.
 const active = activeSelection();
 if (!active.gate.listing) {
  if (active.entry) downloadArchive([active.entry],format,archiveOptions());
  return;
 }
 let entries;
 try { entries = await selectionEntries(); }
 catch(err) { error(err); return; }
 if (!entries.length) return;
 downloadArchive(entries,format,archiveOptions());
 announce(`Preparing ${entries.length.toLocaleString()} item(s) as ${format === 'tgz' ? 'a tar.gz' : 'a ZIP'} archive…`);
}

// contextMenu is the third place that used to decide enablement for itself. It
// now asks the same table the toolbar asks (M4 contract §7.1), over a context
// built from the ONE entry it acts on — which is not always the selection, so
// it is built explicitly rather than read from activeSelection.
//
// A mutating item is DISABLED with its reason, never removed: "never hidden for
// a state reason" (§7.1) applies here too, and a Rename that silently vanishes
// in read-only mode teaches the user that the app is broken.
//
// `anchor` is where it was asked for (stabilization contract §3.7): the pointer
// for a right-click, the focused row for Shift+F10 and the Menu key. Without
// one it opens at the focused row.
export function contextMenu(e,anchor = null) {
 if (!e) return;
 const menu = $('#ctxMenu'); menu.replaceChildren();
 const ctx = whyContext({count:1,one:true,entry:e,kind:kindOf(e,listingActions().listing)});
 const free = label => ({allowed:true,cause:'',sentence:label,causes:[]});
 // Each row is {label, run, why}: `why` is a verdict from the shared table, or
 // a free one for an item nothing can refuse.
 const actions = [
  {label:'Open',run:() => open(e),why:isDirectory(e) ? free('Open this folder') : whyDisabled('viewText',ctx)},
  {label:'Properties',run:() => properties(e),why:whyDisabled('properties',ctx)},
  {label:'Copy full path',run:async () => { try { await navigator.clipboard.writeText(e.path); announce('Path copied.'); } catch { error(new Error('Could not copy the path. Use the path field to copy it.')); } },why:free('Copy this item’s full path')},
 ];
 // The download group, kept together: the plain download where it applies, then
 // the two archive forms — the only way a FOLDER can be downloaded at all, and
 // a legitimate way to take a file with its name intact (contract §2.4).
 const downloads = [
  {label:'Download as ZIP',run:() => downloadArchive([e],'zip',archiveOptions()),why:free('Download this item as a ZIP archive')},
  {label:'Download as tar.gz',run:() => downloadArchive([e],'tgz',archiveOptions()),why:free('Download this item as a tar.gz archive')},
 ];
 if (isReadable(e) || isSymlink(e) && !hasTarget(e)) downloads.unshift(
  {label:'View text',run:() => view(e),why:whyDisabled('viewText',ctx)},
  {label:'Download',run:() => download(e),why:whyDisabled('download',{...ctx,count:isReadable(e) ? 1 : 0})},
 );
 actions.splice(1,0,...downloads);
 if (isSymlink(e) && (e.targetType === 'dir' || !hasTarget(e))) {
  actions.push({label:'Go to target',run:() => { location.hash = route(fileTarget(e)); },
   why:hasTarget(e) ? free('Go to the folder this link points at') : {allowed:false,cause:'selection',sentence:actionHint(e),causes:['selection']}});
 }
 for (const extra of extraActions) {
  if (extra.show && !extra.show(e)) continue;
  actions.push({label:extra.label,run:() => extra.run(e),
   why:extra.action ? whyDisabled(extra.action,ctx) : extra.disabled?.(e) ? {allowed:false,cause:'selection',sentence:actionHint(e),causes:['selection']} : free(extra.label)});
 }
 actions.forEach((entry,index) => {
  const button = el('button',{role:'menuitem',tabindex:'-1',id:`ctxItem-${index}`},entry.label);
  button.addEventListener('click',() => { menu.hidden=true; entry.run(); });
  menu.append(button);
 });
 // applyWhy after the append: the describedby node it points at only helps once
 // the button is in the document.
 actions.forEach((entry,index) => applyWhy(`#ctxItem-${index}`,entry.why));
 menu.hidden=false;
 placeMenuAt(menu,anchor);
 const first=menu.querySelector('button:not(:disabled)');
 if (first) { first.tabIndex=0; first.focus?.(); }
}

// placeMenuAt puts the open menu at its anchor, inside the viewport
// (stabilization contract §3.7). It is measured first at the top-left corner,
// where it has the whole width to lay out in — measured where it last stood, a
// menu that had opened near the right edge would report the narrower width it
// was squeezed to there — and then moved to where menuPlacement says. Both
// writes land before the browser paints, so neither position is ever seen but
// the last.
function placeMenuAt(menu,anchor) {
 placeMenu(0,0);
 const box = menu.getBoundingClientRect?.();
 if (!box) return;
 const root = document.documentElement;
 const viewport = {width:root?.clientWidth || window.innerWidth || 0,height:root?.clientHeight || window.innerHeight || 0};
 const at = anchor || rowAnchor() || listAnchor();
 const {left,top} = menuPlacement({viewport,anchor:at,menu:{width:box.width,height:box.height}});
 placeMenu(left,top);
}

// rowAnchor is the keyboard's "here": the focused row's left edge, top to
// bottom, so the menu opens just below the row the keys were acting on — or,
// flipped, just above it, never over it.
function rowAnchor(index = state.focus) {
 const box = document.getElementById(`row-${index}`)?.getBoundingClientRect?.();
 return box ? {left:box.left,right:box.left,top:box.top,bottom:box.bottom} : null;
}

// listAnchor is the last resort, for a focused row that is not painted: the
// top-left corner of the list itself, which is at least where the user is
// looking.
function listAnchor() {
 const box = $('#listViewport')?.getBoundingClientRect?.();
 return box ? {left:box.left,right:box.left,top:box.top,bottom:box.top} : {left:0,top:0};
}

// pointerAnchor is a right-click's "here": the pointer. A contextmenu event the
// KEYBOARD raised on a row (the Menu key, Shift+F10) carries coordinates that
// are not a pointer at all — 0,0 in one browser, somewhere on the element in
// another — so a position outside the row it was raised on is read as exactly
// that, and the menu opens at the row instead, as the key handler would have
// opened it.
function pointerAnchor(ev,row) {
 const x = Number(ev?.clientX),y = Number(ev?.clientY);
 const box = row?.getBoundingClientRect?.();
 const inside = Number.isFinite(x) && Number.isFinite(y) && (!box || x >= box.left && x <= box.right && y >= box.top && y <= box.bottom);
 if (inside) return {left:x,right:x,top:y,bottom:y};
 return box ? {left:box.left,right:box.left,top:box.top,bottom:box.bottom} : null;
}

export function initList() {
 subscribe(() => {
  if (!state.session) { for (const id of ['#btnDownload','#btnDownloadAs','#btnView','#btnProps','#btnPerms','#btnMkdir','#btnUpload','#btnRename','#btnDelete','#btnCopy','#btnMove','#btnSearch']) $(id).disabled=true; topHeight?.(0); bottomHeight?.(0); }
  else refreshToolbar();
 });
 topHeight = heightRule('#listSpacer'); bottomHeight = heightRule('#listTail');
 placeMenu = placeRule('#ctxMenu');
 // The empty state's single offer (§8.1: one sentence plus at most one action)
 // presses the real toolbar button, so the action it offers is the action the
 // reason table has already judged — never a second path into the same work.
 $('#listEmptyAction').addEventListener('click',() => { if (emptyAction) $(`#${emptyAction}`)?.click?.(); });
 $('#listViewport').addEventListener('scroll',render); window.addEventListener('resize',render);
 $('#searchBox').addEventListener('input',ev => filterTo(ev.target.value));
 $('#listHead').addEventListener('click',ev => {
  const button = ev.target.closest('[data-sort]'); if (!button) return;
  update({sort:button.dataset.sort,desc:state.sort === button.dataset.sort ? !state.desc : false});
  for (const b of $('#listHead').querySelectorAll('button')) { b.parentElement.setAttribute('aria-sort',b===button ? state.desc ? 'descending' : 'ascending' : 'none'); b.textContent = ({name:'Name',size:'Size',type:'Kind',mtime:'Modified'})[b.dataset.sort]+(b===button ? state.desc ? ' ↓' : ' ↑' : ''); }
  loadList();
 });
 $('#btnDownload').addEventListener('click',() => {
  const {count,entry,one} = activeSelection();
  if (downloadMode({count,entry:one ? entry : null}) === 'file') download(entry); else downloadSelection('zip');
 });
 $('#btnView').addEventListener('click',() => view(activeSelection().entry)); $('#btnProps').addEventListener('click',() => properties(activeSelection().entry));
 // The "Download as…" menu. It is CSS-positioned under its button (no inline
 // styles anywhere in this app), and closes on a choice, on Escape, or on a
 // pointer landing anywhere else.
 const dlMenu = $('#dlMenu');
 const closeDownloadMenu = () => { dlMenu.hidden = true; $('#btnDownloadAs').setAttribute('aria-expanded','false'); };
 $('#btnDownloadAs').addEventListener('click',() => {
  const open = dlMenu.hidden;
  dlMenu.hidden = !open; $('#btnDownloadAs').setAttribute('aria-expanded',String(open));
  if (open) $('#dlZip').focus();
 });
 $('#dlZip').addEventListener('click',() => { closeDownloadMenu(); downloadSelection('zip'); });
 $('#dlTgz').addEventListener('click',() => { closeDownloadMenu(); downloadSelection('tgz'); });
 dlMenu.addEventListener('keydown',ev => {
  const items = [...dlMenu.querySelectorAll('button')],i = items.indexOf(document.activeElement);
  if (ev.key === 'Escape') { closeDownloadMenu(); $('#btnDownloadAs').focus(); }
  else if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') { ev.preventDefault(); items[(i+(ev.key === 'ArrowDown' ? 1 : items.length-1))%items.length].focus(); }
 });
 document.addEventListener('pointerdown',ev => { if (!dlMenu.contains(ev.target) && ev.target !== $('#btnDownloadAs')) closeDownloadMenu(); });
 $('#list').addEventListener('keydown',ev => {
  if (ev.target.closest('#listHead')) return;
  const ctrl = ev.ctrlKey || ev.metaKey;
  let index;
  switch(ev.key) {
  case 'ArrowUp': index=state.focus-1; break;
  case 'ArrowDown': index=state.focus+1; break;
  case 'Home': index=0; break;
  case 'End': index=state.total-1; break;
  case 'PageUp': index=state.focus-Math.floor($('#listViewport').clientHeight/rowHeight()); break;
  case 'PageDown': index=state.focus+Math.floor($('#listViewport').clientHeight/rowHeight()); break;
  case ' ': select(state.focus,{toggle:true}); focusRow(); break;
  case 'a': case 'A': if (!ctrl) return; selectAll(); break;
  case 'Enter': if (ev.altKey) properties(focused()); else open(focused()); break;
  case 'F4': view(focused()); break;
  case 'ContextMenu': contextMenu(focused(),rowAnchor()); break;
  case 'F10': if (!ev.shiftKey) return; contextMenu(focused(),rowAnchor()); break;
  case 'Escape': update({selection:new Map()}); syncSelection(); break;
  default:
   if (ev.key.length===1 && !ctrl && !ev.altKey) {
    typeAhead = Date.now()-typedAt > 700 ? ev.key : typeAhead+ev.key; typedAt=Date.now();
    for (const [p,entries] of state.pages) { const n = entries.findIndex(e => e.name.toLocaleLowerCase().startsWith(typeAhead.toLocaleLowerCase())); if (n>=0) { move(p*pageSize+n,ev).catch(error); break; } }
   }
   return;
  }
  ev.preventDefault(); if (index !== undefined) move(index,ev).catch(error);
 });
 const menu = $('#ctxMenu');
 menu.addEventListener('keydown',ev => {
  const items=[...menu.querySelectorAll('button:not(:disabled)')], i=items.indexOf(document.activeElement);
  if (ev.key==='Escape') { menu.hidden=true; focusRow(); }
  else if (ev.key==='ArrowDown' || ev.key==='ArrowUp') { ev.preventDefault(); items[(i+(ev.key==='ArrowDown' ? 1 : items.length-1))%items.length].focus(); }
 });
 // The Menu key and Shift+F10 make the browser raise a contextmenu event of its
 // own as well, and by then focus is on this menu: its native menu would open
 // on top of ours. Nothing in this menu has a context of its own to offer.
 menu.addEventListener('contextmenu',ev => ev.preventDefault());
 document.addEventListener('pointerdown',ev => { if (!menu.contains(ev.target)) menu.hidden=true; });
}
