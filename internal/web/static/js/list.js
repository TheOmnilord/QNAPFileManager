import {api} from './api.js';
import {$,el,error,pathArgs,route,heightRule,announce} from './dom.js';
import {state,update,selected,countSelected,subscribe,sessionGuard} from './state.js';
import {nameCell,isDirectory,isReadable,isSymlink,hasTarget,fileTarget,actionHint,directoryNotice} from './badges.js';
import {view,download,properties} from './viewer.js';
const DEFAULT_PAGE = 500;
let pageSize = DEFAULT_PAGE;
let topHeight,bottomHeight;
const pending = new Map();
let typeAhead = '', typedAt = 0;
const rowHeight = () => matchMedia('(max-width:30rem)').matches ? 44 : 36;
export const entryAt = index => state.pages.get(Math.floor(index/pageSize))?.[index%pageSize];
export const focused = () => entryAt(state.focus);
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
const navigable = e => e && !(e.volumeRoot && state.path==='/share') && (!state.filter || e.name.toLocaleLowerCase().includes(state.filter.toLocaleLowerCase()));
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
 } catch(err) { if (valid() && generation === state.generation) { update({loading:false}); error(err); } }
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
 $('#status').textContent = `${n.toLocaleString()} of ${state.total.toLocaleString()} selected · ${state.path} · ${state.session?.family || ''} · ${mode}${state.filter ? ' · Filtering loaded names only' : ''}`;
 refreshToolbar();
}

// refreshToolbar reflects the current selection and the session's write
// capability onto every action button. Mutating buttons are disabled (never
// hidden) with a title saying why, per the safety plan §3.2/§4.1.
export function refreshToolbar() {
 const n = countSelected(), e = focused(), one = n === 1 && e && selected(state.focus);
 const canWrite = !!state.session?.canWrite;
 $('#btnDownload').disabled = !one || !isReadable(e);
 $('#btnView').disabled = !one || !isReadable(e);
 const hint = one && !isReadable(e) ? actionHint(e) : '';
 $('#btnDownload').title = hint; $('#btnView').title = hint;
 $('#btnProps').disabled = !one;
 const ro = 'Read-only mode is on. Turn it off in Settings to make changes.';
 $('#btnMkdir').disabled = !canWrite;
 $('#btnMkdir').title = canWrite ? 'New folder' : ro;
 $('#btnRename').disabled = !canWrite || n !== 1;
 $('#btnRename').title = !canWrite ? ro : (n !== 1 ? 'Select one item to rename.' : 'Rename');
 $('#btnDelete').disabled = !canWrite || n < 1;
 $('#btnDelete').title = !canWrite ? ro : (n < 1 ? 'Select items to delete.' : 'Delete');
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
  const match = !state.filter || e.name.toLocaleLowerCase().includes(state.filter.toLocaleLowerCase());
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

export function contextMenu(e) {
 if (!e) return;
 const menu = $('#ctxMenu'); menu.replaceChildren();
 const actions = [['Open',() => open(e),!isDirectory(e) && !isReadable(e)],['Properties',() => properties(e)],['Copy full path',async () => { try { await navigator.clipboard.writeText(e.path); announce('Path copied.'); } catch { error(new Error('Could not copy the path. Use the path field to copy it.')); } }]];
 if (isReadable(e) || isSymlink(e) && !hasTarget(e)) actions.splice(1,0,['View text',() => view(e),!isReadable(e)],['Download',() => download(e),!isReadable(e)]);
 if (isSymlink(e) && (e.targetType === 'dir' || !hasTarget(e))) actions.push(['Go to target',() => { location.hash = route(fileTarget(e)); },!hasTarget(e)]);
 for (const a of extraActions) if (!a.show || a.show(e)) actions.push([a.label,() => a.run(e),a.disabled?.(e)]);
 for (const [label,action,disabled] of actions) { const b = el('button',{role:'menuitem',tabindex:'-1'},label); b.disabled=!!disabled; if (disabled) b.title=actionHint(e); b.addEventListener('click',() => { menu.hidden=true; action(); }); menu.append(b); }
 menu.hidden=false; const first=menu.querySelector('button:not(:disabled)'); first.tabIndex=0; first.focus();
}

export function initList() {
 subscribe(() => {
  if (!state.session) { for (const id of ['#btnDownload','#btnView','#btnProps','#btnMkdir','#btnRename','#btnDelete']) $(id).disabled=true; topHeight?.(0); bottomHeight?.(0); }
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
 $('#btnDownload').addEventListener('click',() => download(focused())); $('#btnView').addEventListener('click',() => view(focused())); $('#btnProps').addEventListener('click',() => properties(focused()));
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
