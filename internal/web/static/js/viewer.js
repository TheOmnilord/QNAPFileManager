import {api,apiURL} from './api.js';
import {$,el,pathArgs,openDialog,error} from './dom.js';
import {isReadable,fileTarget} from './badges.js';
import {sessionGuard} from './state.js';
let current;
export function download(entry) {
 if (!entry || !isReadable(entry)) return;
 const link = el('a',{href:apiURL('api/fs/download',pathArgs(fileTarget(entry))),download:entry.name});
 document.body.append(link); link.click(); link.remove();
}
export async function view(entry) {
 if (!entry || !isReadable(entry)) return;
 const valid=sessionGuard();
 current = entry; $('#viewerTitle').textContent = entry.path;
 $('#viewerContent').textContent = 'Loading…'; $('#viewerNote').textContent = 'Read-only'; openDialog('#dlgViewer');
 try {
  const data = await api('api/fs/text',pathArgs(fileTarget(entry)));
  if (!valid() || !$('#dlgViewer').open || current !== entry) return;
  $('#viewerContent').textContent = data.binary ? 'This file contains binary data. Download it to view it in another application.' : data.content;
  $('#viewerNote').textContent = `${data.bytes.toLocaleString()} bytes · ${data.mode} · read-only${data.truncated ? ' · Preview truncated' : ''}`;
 } catch(err) { if (valid() && $('#dlgViewer').open && current === entry) { $('#viewerContent').textContent = err.message; error(err); } }
}
// propsEntry is what the Properties dialog is currently showing, so "Calculate
// size" (jobs.js) knows what to measure without viewer.js importing the job
// module — which would close an import cycle through list.js.
let propsEntry = null;
export const propsTarget = () => propsEntry;
export async function properties(entry) {
 if (!entry) return;
 const valid=sessionGuard();
 try {
  const data = await api('api/fs/stat',pathArgs(entry));
  if (!valid()) return;
  propsEntry = entry;
  $('#propsContent').textContent = Object.entries(data).map(([k,v]) => `${k}: ${v}`).join('\n');
  $('#propsSize').textContent = ''; $('#btnCalcSize').disabled = false;
  openDialog('#dlgProps');
 } catch(err) { if (valid()) error(err); }
}
export function initViewer() { $('#viewerDownload').addEventListener('click',() => download(current)); }
