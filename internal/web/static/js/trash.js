import {api} from './api.js';
import {$,el,error,announce,openDialog} from './dom.js';
import {state,sessionGuard} from './state.js';
import {confirmDialog,PERMANENT_WARNING} from './actions.js';
import {trackJob,formatBytes} from './jobs.js';

// The trash panel (ui-ux §4.4). It lists only the caller's own items — the
// kernel's sticky bit on .@qfm_trash is what makes that true, not this code —
// and it discloses where the trash actually lives, because the daemon created
// those directories on the user's volumes (PLAN.md decision 10).

let items = [];

// trashRow renders one item. The checkbox carries the id; the id is the
// worker's entry-directory name, never a path.
function trashRow(item) {
 const row = el('tr',{});
 const cell = el('td',{});
 const box = el('input',{type:'checkbox',class:'trashPick',value:item.id});
 box.setAttribute('aria-label',`Select ${item.name}`);
 cell.append(box);
 row.append(cell);
 row.append(el('td',{title:item.name},item.name));
 row.append(el('td',{title:item.origPath},item.origPath));
 row.append(el('td',{},item.deletedAt ? new Date(item.deletedAt*1000).toLocaleString() : '—'));
 // The size is the whole item's — the whole tree, for a folder, which the
 // worker counted when it moved it — and -1 is the worker saying it does not
 // know. A folder used to be shown as "—" always, because the only number there
 // was the directory inode's own (4 096 bytes, whatever the tree held).
 const size = Number(item.size);
 const known = Number.isFinite(size) && size >= 0;
 row.append(el('td',known ? {title:`${size.toLocaleString()} bytes`} : {},known ? formatBytes(size) : '—'));
 return row;
}

export async function loadTrash() {
 if (!state.session) return;
 const valid = sessionGuard();
 $('#trashStatus').textContent = 'Loading…';
 try {
  const data = await api('api/trash');
  if (!valid()) return;
  items = data.items || [];
  $('#trashRows').replaceChildren(...items.map(trashRow));
  $('#trashEmpty').hidden = items.length > 0;
  $('#trashStatus').textContent = `${items.length.toLocaleString()} item(s) in Trash.`;
  $('#trashWhere').textContent = `Trash lives in ${data.dirName || '.@qfm_trash'} on each volume.`;
 } catch(err) { if (valid()) { $('#trashStatus').textContent = err.message; error(err); } }
}

function picked() { return [...document.querySelectorAll('.trashPick')].filter(box => box.checked).map(box => box.value); }

async function restore() {
 const ids = picked();
 if (!ids.length) { announce('Select items to restore.'); return; }
 const valid = sessionGuard();
 try {
  const res = await api('api/trash/restore',{},{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids})});
  if (!valid()) return;
  trackJob(res.job);
  announce(`Restoring ${ids.length.toLocaleString()} item(s).`);
  $('#dlgTrash').close();
 } catch(err) { if (valid()) error(err); }
}

// empty is the canonical grade-2 action: a typed phrase plus the server's own
// "cannot be undone" sentence, then a redeemed token.
async function empty() {
 const valid = sessionGuard();
 const post = body => api('api/trash/empty',{},{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 try {
  await post({});
 } catch(err) {
  if (!valid()) return;
  if (err.code!=='confirm_required' || !err.confirm?.token) { error(err); return; }
  const s = err.confirm.summary||{};
  // The server's own warnings come first; the count and the size follow. The
  // size is read in units rather than in raw bytes, and it is what the server
  // could actually total — any item it could not measure is one of the warnings
  // above this line.
  const why = [...(s.warnings||[]),`${(s.files||0).toLocaleString()} item(s), ${formatBytes(s.bytes||0)}.`]
   .filter((line,index,all) => line && all.indexOf(line)===index).join(' · ');
  const approved = await confirmDialog({
   title:'Empty Trash',
   body:'Permanently delete everything in your Trash?',
   why: why || PERMANENT_WARNING,
   danger:true,
   phrase:'empty',
  });
  if (!valid()) return;
  if (!approved) return;
  try {
   const res = await post({confirm:err.confirm.token});
   if (!valid()) return;
   trackJob(res.job);
   announce('Emptying Trash.');
   $('#dlgTrash').close();
  } catch(err2) { if (valid()) error(err2); }
  return;
 }
 // A 2xx with no challenge would mean the server stopped requiring a token,
 // which it never does; say so rather than silently succeeding.
 if (valid()) error(new Error('Emptying Trash was not confirmed. Try again.'));
}

export function openTrash() { openDialog('#dlgTrash'); loadTrash(); }

export function initTrash() {
 $('#btnTrash').addEventListener('click',openTrash);
 $('#btnTrashRefresh').addEventListener('click',loadTrash);
 $('#btnTrashRestore').addEventListener('click',restore);
 $('#btnTrashEmpty').addEventListener('click',empty);
 $('#trashAll').addEventListener('change',ev => { for (const box of document.querySelectorAll('.trashPick')) box.checked = ev.target.checked; });
}
