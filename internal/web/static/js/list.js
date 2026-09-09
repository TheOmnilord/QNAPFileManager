import {api} from './api.js';
import {$,el,error,pathArgs,route,heightRule,announce} from './dom.js';
import {state,update,selected,countSelected,subscribe} from './state.js';
import {nameCell,isDirectory,isReadable,directoryNotice} from './badges.js';
import {view,download,properties} from './viewer.js';
const PAGE = 500;
let topHeight,bottomHeight;
const pending = new Map();
let typeAhead = '', typedAt = 0;
const rowHeight = () => matchMedia('(max-width:30rem)').matches ? 44 : 36;
export const entryAt = index => state.pages.get(Math.floor(index/PAGE))?.[index%PAGE];
export const focused = () => entryAt(state.focus);
const navigable = e => e && !(e.volumeRoot && state.path==='/share') && (!state.filter || e.name.toLocaleLowerCase().includes(state.filter.toLocaleLowerCase()));
function query(offset) { return {...pathArgs(state),offset,limit:PAGE,sort:state.sort,desc:state.desc,hidden:state.hidden,volumes:false}; }

async function page(number,generation) {
 if (state.pages.has(number)) return;
 const key = `${generation}:${number}`;
 if (pending.has(key)) return pending.get(key);
 const request = (async () => {
  const data = await api('api/fs/list',query(number*PAGE));
  if (generation !== state.generation || !state.session) return;
  const pages = new Map(state.pages); pages.set(number,data.entries);
  update({pages,total:data.total,loading:false});
  if (number === 0) directoryNotice(data);
  render();
 })();
 pending.set(key,request);
 try { await request; } finally { pending.delete(key); }
}

export async function loadList() {
 const generation = state.generation+1;
 update({generation,pages:new Map(),total:0,selection:new Set(),exclude:false,focus:0,anchor:0,loading:true});
 $('#listViewport').scrollTop = 0; $('#status').textContent = 'Loading…'; render();
 try {
  await page(0,generation);
  if (generation !== state.generation) return;
  if (state.total <= 2000) for (let n=1;n<Math.ceil(state.total/PAGE);n++) await page(n,generation);
  render();
 } catch(err) { if (generation === state.generation) { update({loading:false}); error(err); } }
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
 render();
}

function status() {
 const n = countSelected();
 $('#status').textContent = `${n.toLocaleString()} of ${state.total.toLocaleString()} selected · ${state.path} · ${state.session?.family || ''} · read-only browse${state.filter ? ' · Filtering loaded names only' : ''}`;
 const e = focused(), one = n === 1 && e && selected(state.focus);
 $('#btnDownload').disabled = !one || !isReadable(e);
 $('#btnView').disabled = !one || !isReadable(e);
 $('#btnProps').disabled = !one;
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
 $('#list').tabIndex = navigable(focused()) && state.focus >= start && state.focus < end ? -1 : 0;
 $('#list').setAttribute('aria-busy',String(state.loading));
 const rows = [];
 const needed = new Set();
 for (let i=start;i<end;i++) {
  const e = entryAt(i);
  if (!e) { needed.add(Math.floor(i/PAGE)); rows.push(el('div',{class:'fileRow','aria-hidden':'true'},'Loading…')); continue; }
  // Preserve virtual row geometry even while filtering the loaded page.
  const match = !state.filter || e.name.toLocaleLowerCase().includes(state.filter.toLocaleLowerCase());
  const row = el('div',{id:`row-${i}`,role:'row',class:`fileRow ${e.class || ''}${match ? '' : ' filtered'}${e.volumeRoot && state.path==='/share' ? ' volumeRow' : ''}${!isDirectory(e) && !isReadable(e) ? ' special' : ''}`,tabindex:i===state.focus ? '0' : '-1','aria-rowindex':i+2,'aria-selected':selected(i),'data-name':e.name,'data-kind':e.type,'data-idx':i});
  row.append(nameCell(e),el('span',{role:'gridcell'},isDirectory(e) ? '—' : e.size.toLocaleString()),el('span',{role:'gridcell',class:'extra'},e.type),el('span',{role:'gridcell'},new Date(e.mtime).toLocaleString()),el('span',{role:'gridcell',class:'extra'},e.modeStr || e.mode),el('span',{role:'gridcell',class:'extra'},`${e.user || e.uid}:${e.group || e.gid}`));
  row.addEventListener('click',ev => { select(i,ev); focusRow(); if (matchMedia('(max-width:30rem)').matches && !ev.ctrlKey && !ev.shiftKey) open(e); });
  row.addEventListener('dblclick',() => open(e));
  row.addEventListener('contextmenu',ev => { ev.preventDefault(); select(i); contextMenu(e); });
  row.addEventListener('focus',() => { if (state.focus !== i) update({focus:i}); });
  rows.push(row);
 }
 $('#listRows').replaceChildren(...rows);
 $('#listEmpty').hidden = state.loading || state.total !== 0;
 if (hadFocus) focusRow();
 if (!state.loading && state.session) status();
 for (const n of needed) page(n,state.generation).catch(error);
}

function focusRow() { document.getElementById(`row-${state.focus}`)?.focus({preventScroll:true}); }
export function open(e) {
 if (!e) return;
 if (isDirectory(e)) { location.hash = route(e); $('#tree').classList.remove('open'); $('#btnTree').setAttribute('aria-expanded','false'); }
 else view(e);
}
async function move(index,event) {
 index = Math.max(0,Math.min(state.total-1,index));
 if (state.total === 0) return;
 const direction = index < state.focus ? -1 : 1;
 while (entryAt(index) && !navigable(entryAt(index))) {
  index += direction;
  if (index < 0 || index >= state.total) return;
 }
 if (event.ctrlKey || event.metaKey) update({focus:index}); else select(index,event);
 const v = $('#listViewport'),h = rowHeight();
 if (index*h < v.scrollTop) v.scrollTop = index*h;
 if ((index+1)*h > v.scrollTop+v.clientHeight) v.scrollTop = (index+1)*h-v.clientHeight;
 await page(Math.floor(index/PAGE),state.generation); render(); focusRow();
}

export function contextMenu(e) {
 if (!e) return;
 const menu = $('#ctxMenu'); menu.replaceChildren();
 const actions = [['Open',() => open(e)],['Properties',() => properties(e)],['Copy full path',async () => { try { await navigator.clipboard.writeText(e.path); announce('Path copied.'); } catch { error(new Error('Could not copy the path. Use the path field to copy it.')); } }]];
 if (isReadable(e)) actions.splice(1,0,['View text',() => view(e)],['Download',() => download(e)]);
 if (e.linkResolved) actions.push(['Go to symlink target',() => { location.hash = route({path:e.linkResolved}); }]);
 for (const [label,action] of actions) { const b = el('button',{role:'menuitem',tabindex:'-1'},label); b.addEventListener('click',() => { menu.hidden=true; action(); }); menu.append(b); }
 menu.hidden=false; menu.firstElementChild.tabIndex=0; menu.firstElementChild.focus();
}

export function initList() {
 subscribe(() => { if (!state.session) { $('#btnDownload').disabled=true; $('#btnView').disabled=true; $('#btnProps').disabled=true; topHeight?.(0); bottomHeight?.(0); } });
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
  case 'a': case 'A': if (!ctrl) return; update({exclude:true,selection:new Set()}); render(); break;
  case 'Enter': if (ev.altKey) properties(focused()); else open(focused()); break;
  case 'F4': view(focused()); break;
  case 'ContextMenu': contextMenu(focused()); break;
  case 'F10': if (!ev.shiftKey) return; contextMenu(focused()); break;
  case 'Escape': update({selection:new Set(),exclude:false}); render(); break;
  default:
   if (ev.key.length===1 && !ctrl && !ev.altKey) {
    typeAhead = Date.now()-typedAt > 700 ? ev.key : typeAhead+ev.key; typedAt=Date.now();
    for (const [p,entries] of state.pages) { const n = entries.findIndex(e => e.name.toLocaleLowerCase().startsWith(typeAhead.toLocaleLowerCase())); if (n>=0) { move(p*PAGE+n,ev).catch(error); break; } }
   }
   return;
  }
  ev.preventDefault(); if (index !== undefined) move(index,ev).catch(error);
 });
 const menu = $('#ctxMenu');
 menu.addEventListener('keydown',ev => {
  const items=[...menu.children], i=items.indexOf(document.activeElement);
  if (ev.key==='Escape') { menu.hidden=true; focusRow(); }
  else if (ev.key==='ArrowDown' || ev.key==='ArrowUp') { ev.preventDefault(); items[(i+(ev.key==='ArrowDown' ? 1 : items.length-1))%items.length].focus(); }
 });
 document.addEventListener('pointerdown',ev => { if (!menu.contains(ev.target)) menu.hidden=true; });
}
