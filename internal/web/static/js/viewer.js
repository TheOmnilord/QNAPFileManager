import {api,apiURL} from './api.js';
import {$,el,pathArgs,openDialog,error} from './dom.js';
import {isReadable,fileTarget} from './badges.js';
let current;
export function download(entry) {
 if (!entry || !isReadable(entry)) return;
 const link = el('a',{href:apiURL('api/fs/download',pathArgs(fileTarget(entry))),download:entry.name});
 document.body.append(link); link.click(); link.remove();
}
export async function view(entry) {
 if (!entry || !isReadable(entry)) return;
 current = entry; $('#viewerTitle').textContent = entry.path;
 $('#viewerContent').textContent = 'Loading…'; $('#viewerNote').textContent = 'Read-only'; openDialog('#dlgViewer');
 try {
  const data = await api('api/fs/text',pathArgs(fileTarget(entry)));
  if (!$('#dlgViewer').open || current !== entry) return;
  $('#viewerContent').textContent = data.binary ? 'This file contains binary data. Download it to view it in another application.' : data.content;
  $('#viewerNote').textContent = `${data.bytes.toLocaleString()} bytes · ${data.mode} · read-only${data.truncated ? ' · Preview truncated' : ''}`;
 } catch(err) { $('#viewerContent').textContent = err.message; error(err); }
}
export async function properties(entry) {
 if (!entry) return;
 try {
  const data = await api('api/fs/stat',pathArgs(entry));
  $('#propsContent').textContent = Object.entries(data).map(([k,v]) => `${k}: ${v}`).join('\n'); openDialog('#dlgProps');
 } catch(err) { error(err); }
}
export function initViewer() { $('#viewerDownload').addEventListener('click',() => download(current)); }
