import {api} from './api.js';
import {$,el,error,pathArgs,route,heightRule,announce} from './dom.js';
import {state,update,selected,countSelected,subscribe,sessionGuard,listingActions} from './state.js';
import {nameCell,isDirectory,isReadable,isSymlink,hasTarget,fileTarget,actionHint,directoryNotice} from './badges.js';
import {view,download,downloadMode,downloadArchive} from './viewer.js';
import {properties} from './props.js';
// pathBytes is the byte spelling of a path reference. It lives in transfer.js
// because that is where the rule was first needed (a destination that IS one of
// the copied items), and there must be exactly one of it: two implementations
// of "are these the same file" is how the lookalike bug gets reintroduced.
import {pathBytes} from './transfer.js';
const DEFAULT_PAGE = 500;
let pageSize = DEFAULT_PAGE;
let topHeight,bottomHeight;
const pending = new Map();
let typeAhead = '', typedAt = 0;
const rowHeight = () => matchMedia('(max-width:30rem)').matches ? 44 : 36;
export const entryAt = index => state.pages.get(Math.floor(index/pageSize))?.[index%pageSize];
export const focused = () => entryAt(state.focus);
// selectedOne resolves the single SELECTED entry, or null when the selection is
// not exactly one item, or when focus has moved off the selected row (Ctrl+Arrow
// moves focus without changing the selection). Rename and Properties act on this,
// never on focused() alone, so a toolbar action cannot target a focused-but-
// unselected entry (standard P2 / round-3 finding 7).
export const selectedOne = () => { const e = focused(); return countSelected() === 1 && e && selected(state.focus) ? e : null; };
// extraActions lets other modules (actions.js) contribute context-menu items
// without list.js importing them, which would create a cycle. Each is
// {label, run(entry), show?(entry), disabled?(entry)}.
export const extraActions = [];
// selectionEntries resolves the explicit selection to its entries, in order,
// fetching any pages that hold selected rows but were never loaded. A directory
// larger than 2,000 entries loads lazily, so a Shift-range can select indices on
// pages that are not in state.pages; the old synchronous selectedEntries silently
// dropped those, so a delete of such a selection removed only the loaded subset
// while reporting success (standard P2). This awaits the missing pages and
// refuses — throwing a clear Error — rather than ever returning a truncated set.
// It returns null in select-all (exclude) mode, which M1 mutations do not
// support.
export async function selectionEntries() {
 if (state.exclude) return null;
 const indices=[...state.selection].sort((a,b) => a-b);
 const generation=state.generation;
 const needed=new Set();
 for (const i of indices) if (!entryAt(i)) needed.add(Math.floor(i/pageSize));
 for (const n of needed) {
  await page(n,generation);
  if (generation!==state.generation || !state.session) throw new Error('The listing changed while preparing the selection. Try again.');
 }
 const entries=indices.map(entryAt);
 if (entries.some(e => !e)) throw new Error('Some selected items are still loading. Scroll through the selection to load them, or select fewer items, then try again.');
 return entries;
}
// matchesFilter is the quick filter's rule, in ONE place. navigable() and
// render() both decide what a row does by this test, and so must anything that
// reasons about whether a row can be SEEN (revealFilter, below) — two spellings
// of the same predicate is how they drift apart.
export const matchesFilter = (filter,name) =>
 !filter || String(name ?? '').toLocaleLowerCase().includes(String(filter).toLocaleLowerCase());
const navigable = e => e && !(e.volumeRoot && state.path==='/share') && matchesFilter(state.filter,e.name);
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
  const pages = new Map(state.pages); pages.set(number,data.entries);
  update({pages,total:data.total,loading:false});
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
 update({generation,pages:new Map(),total:0,selection:new Set(),exclude:false,focus:0,anchor:0,loading:true});
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
 } catch(err) { if (valid() && generation === state.generation) { update({loading:false,pendingReveal:null}); error(err); } }
}

function select(index,event={}) {
 const set = new Set(state.selection);
 let exclude = state.exclude;
 if (event.shiftKey) {
  const a = Math.min(state.anchor,index), b = Math.max(state.anchor,index);
  // Range selection stores just indices; it never fetches the whole directory.
  for (let i=a;i<=b;i++) exclude ? set.delete(i) : set.add(i);
 } else if (event.ctrlKey || event.metaKey || event.toggle) {
  set.has(index) ? set.delete(index) : set.add(index);
 } else { set.clear(); set.add(index); exclude = false; }
 update({selection:set,exclude,focus:index,anchor:event.shiftKey ? state.anchor : index});
 syncSelection();
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
// resultHint is actionHint for a row in the RESULTS view, where a symlink's
// target was never inspected. Kept here rather than imported from search.js so
// the two modules do not close a cycle over a one-line sentence.
const resultHint = e => isSymlink(e) && !hasTarget(e)
 ? 'Search does not follow symlinks, so this one’s target was not inspected. Open its folder to see where it points.'
 : actionHint(e);

export function activeSelection() {
 const gate = listingActions();
 if (!gate.listing) {
  const found = state.searchResults,hit = found?.hits?.[found?.focus] ?? null;
  return {gate,count:hit ? 1 : 0,entry:hit,one:!!hit};
 }
 const e = focused();
 return {gate,count:gate.count,entry:e,one:gate.count === 1 && !!e && selected(state.focus)};
}

// refreshToolbar reflects the current selection and the session's write
// capability onto every action button. Mutating buttons are disabled (never
// hidden) with a title saying why, per the safety plan §3.2/§4.1 — and while
// the search results are up, "why" is that the listing is not on screen.
export function refreshToolbar() {
 const {gate,count:n,entry:e,one} = activeSelection();
 const canWrite = !!state.session?.canWrite && gate.mutate;
 // The Download button is a SPLIT (contract §2.4): one readable file leaves as
 // itself, anything else — a folder, or several items — leaves as a ZIP, and
 // the ▾ menu offers tar.gz instead. The button says which it will do, so the
 // click is never a surprise.
 const mode = downloadMode({count:n,entry:one ? e : null});
 $('#btnDownload').disabled = mode === 'none';
 $('#btnDownload').textContent = mode === 'archive' ? 'Download as ZIP' : 'Download';
 $('#btnDownloadAs').disabled = mode === 'none';
 $('#btnView').disabled = !one || !isReadable(e);
 // View stays disabled for an unresolved link either way — the kind is not
 // known to be readable — but the REASON differs, and only the context knows
 // which it is. The listing follows symlinks, so an unresolved one there really
 // is broken; a search hit was never followed, so calling it broken states
 // something nobody checked (round 10).
 const hint = one && !isReadable(e)
  ? (gate.listing ? actionHint(e) : resultHint(e))
  : '';
 $('#btnDownload').title = mode === 'archive' ? 'Download the selection as a ZIP archive' : hint;
 $('#btnView').title = hint;
 $('#btnProps').disabled = !one;
 // Two different reasons a change is refused, said apart: read-only mode, and
 // "the listing is not what you are looking at". Saying "read-only mode is on"
 // for the second would be a lie the user would go and check in Settings.
 const paused = 'Close the search results to change files in this folder.';
 const ro = !gate.mutate ? paused : 'Read-only mode is on. Turn it off in Settings to make changes.';
 $('#btnMkdir').disabled = !canWrite;
 $('#btnMkdir').title = canWrite ? 'New folder' : ro;
 $('#btnUpload').disabled = !canWrite;
 $('#btnUpload').title = canWrite ? 'Upload files into this folder (or drop them on the list)' : ro;
 // Searching is reading: it needs a session, never write permission.
 $('#btnSearch').disabled = false;
 // Permissions acts on the WHOLE selection — a recursive chmod over several
 // roots is one job — so it needs a selection and write permission, and never
 // the owner arithmetic: that is a hint the dialog shows, not a lock (PLAN
 // decision 12, M3 contract §5.2).
 $('#btnPerms').disabled = !canWrite || n < 1;
 $('#btnPerms').title = !canWrite ? ro : (n < 1 ? 'Select items to change permissions.' : 'Permissions (F9)');
 $('#btnRename').disabled = !canWrite || !one;
 $('#btnRename').title = !canWrite ? ro : (!one ? 'Select one item to rename.' : 'Rename');
 $('#btnDelete').disabled = !canWrite || n < 1;
 $('#btnDelete').title = !canWrite ? ro : (n < 1 ? 'Select items to delete.' : 'Delete');
 for (const [id,verb] of [['#btnCopy','copy'],['#btnMove','move']]) {
  $(id).disabled = !canWrite || n < 1;
  $(id).title = !canWrite ? ro : (n < 1 ? `Select items to ${verb}.` : `${verb==='copy' ? 'Copy' : 'Move'} to another folder (Ctrl+${verb==='copy' ? 'C' : 'X'}, then Ctrl+V)`);
 }
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
  row.append(nameCell(e),el('span',{role:'gridcell'},isDirectory(e) ? '—' : e.size.toLocaleString()),el('span',{role:'gridcell',class:'extra'},e.type),el('span',{role:'gridcell'},new Date(e.mtime).toLocaleString()),el('span',{role:'gridcell',class:'extra'},e.modeStr || e.mode),el('span',{role:'gridcell',class:'extra'},`${e.user || e.uid}:${e.group || e.gid}`));
  row.addEventListener('click',ev => { select(i,ev); focusRow(); if (matchMedia('(max-width:30rem)').matches && !ev.ctrlKey && !ev.shiftKey) open(e); });
  row.addEventListener('dblclick',() => open(e));
  row.addEventListener('contextmenu',ev => { ev.preventDefault(); select(i); contextMenu(e); });
  row.addEventListener('focus',() => { if (state.focus !== i) { update({focus:i}); syncSelection(); } });
  rows.push(row);
 }
 $('#listRows').replaceChildren(...rows);
 syncSelection();
 $('#listEmpty').hidden = state.loading || state.total !== 0;
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
 const {clear,note} = revealFilter(state.filter,entryAt(index));
 const patch = {selection:new Set([index]),exclude:false,focus:index,anchor:index};
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
// selection in full or not at all, never from the loaded subset (standard P2).
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
 if (entries === null) { error(new Error('Select items individually to download them as an archive in this version.')); return; }
 if (!entries.length) return;
 downloadArchive(entries,format,archiveOptions());
 announce(`Preparing ${entries.length.toLocaleString()} item(s) as ${format === 'tgz' ? 'a tar.gz' : 'a ZIP'} archive…`);
}

export function contextMenu(e) {
 if (!e) return;
 const menu = $('#ctxMenu'); menu.replaceChildren();
 const actions = [['Open',() => open(e),!isDirectory(e) && !isReadable(e)],['Properties',() => properties(e)],['Copy full path',async () => { try { await navigator.clipboard.writeText(e.path); announce('Path copied.'); } catch { error(new Error('Could not copy the path. Use the path field to copy it.')); } }]];
 // The download group, kept together: the plain download where it applies, then
 // the two archive forms — the only way a FOLDER can be downloaded at all, and
 // a legitimate way to take a file with its name intact (contract §2.4).
 const downloads = [['Download as ZIP',() => downloadArchive([e],'zip',archiveOptions())],['Download as tar.gz',() => downloadArchive([e],'tgz',archiveOptions())]];
 if (isReadable(e) || isSymlink(e) && !hasTarget(e)) downloads.unshift(['View text',() => view(e),!isReadable(e)],['Download',() => download(e),!isReadable(e)]);
 actions.splice(1,0,...downloads);
 if (isSymlink(e) && (e.targetType === 'dir' || !hasTarget(e))) actions.push(['Go to target',() => { location.hash = route(fileTarget(e)); },!hasTarget(e)]);
 for (const a of extraActions) if (!a.show || a.show(e)) actions.push([a.label,() => a.run(e),a.disabled?.(e)]);
 for (const [label,action,disabled] of actions) { const b = el('button',{role:'menuitem',tabindex:'-1'},label); b.disabled=!!disabled; if (disabled) b.title=actionHint(e); b.addEventListener('click',() => { menu.hidden=true; action(); }); menu.append(b); }
 menu.hidden=false; const first=menu.querySelector('button:not(:disabled)'); first.tabIndex=0; first.focus();
}

export function initList() {
 subscribe(() => {
  if (!state.session) { for (const id of ['#btnDownload','#btnDownloadAs','#btnView','#btnProps','#btnPerms','#btnMkdir','#btnUpload','#btnRename','#btnDelete','#btnCopy','#btnMove','#btnSearch']) $(id).disabled=true; topHeight?.(0); bottomHeight?.(0); }
  else refreshToolbar();
 });
 topHeight = heightRule('#listSpacer'); bottomHeight = heightRule('#listTail');
 $('#listViewport').addEventListener('scroll',render); window.addEventListener('resize',render);
 $('#searchBox').addEventListener('input',ev => { update({filter:ev.target.value}); render(); });
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
  case 'a': case 'A': if (!ctrl) return; update({exclude:true,selection:new Set()}); syncSelection(); break;
  case 'Enter': if (ev.altKey) properties(focused()); else open(focused()); break;
  case 'F4': view(focused()); break;
  case 'ContextMenu': contextMenu(focused()); break;
  case 'F10': if (!ev.shiftKey) return; contextMenu(focused()); break;
  case 'Escape': update({selection:new Set(),exclude:false}); syncSelection(); break;
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
 document.addEventListener('pointerdown',ev => { if (!menu.contains(ev.target)) menu.hidden=true; });
}
