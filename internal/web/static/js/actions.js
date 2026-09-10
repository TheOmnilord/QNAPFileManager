import {api} from './api.js';
import {$,el,error,announce,openDialog,pathArgs} from './dom.js';
import {state,sessionGuard} from './state.js';
import {loadList,focused,selectedEntries,extraActions} from './list.js';
import {loadTree} from './tree.js';

// post sends a JSON body to a mutation route. api() attaches the CSRF header and
// throws an Error carrying .code and, for a 409, .confirm.
function post(endpoint,body) {
 return api(endpoint,{},{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
}

// runMutation posts body to endpoint and drives the server confirmation-token
// flow. On a 409 confirm_required it calls ask(confirm,message); if that
// resolves truthy it re-posts the identical body plus the token, otherwise it
// returns null (cancelled). This helper is pure (no DOM) so it can be unit
// tested with a mocked api.
export async function runMutation(endpoint,body,ask) {
 try {
  return await post(endpoint,body);
 } catch(err) {
  if (err.code==='confirm_required' && err.confirm?.token) {
   const approved=await ask(err.confirm,err.message);
   if (!approved) return null;
   return await post(endpoint,{...body,confirm:err.confirm.token});
  }
  throw err;
 }
}

// promptDialog resolves to the entered string, or null if cancelled.
function promptDialog({title,label,value=''}) {
 return new Promise(resolve => {
  const dlg=$('#dlgPrompt'),input=$('#promptInput'),ok=$('#promptOK');
  $('#promptTitle').textContent=title; $('#promptLabel').textContent=label; input.value=value;
  const cleanup=() => { ok.removeEventListener('click',onOK); dlg.removeEventListener('close',onClose); };
  const onOK=() => { cleanup(); resolve(input.value); dlg.close(); };
  const onClose=() => { cleanup(); resolve(null); };
  ok.addEventListener('click',onOK); dlg.addEventListener('close',onClose);
  openDialog('#dlgPrompt'); input.focus?.(); input.select?.();
 });
}

// confirmDialog resolves to true only when confirmed. When phrase is set, the
// OK button stays disabled until the typed text matches it exactly.
function confirmDialog({title,body,why='',danger=false,phrase=''}) {
 return new Promise(resolve => {
  const dlg=$('#dlgConfirm'),ok=$('#confirmOK'),input=$('#confirmPhrase'),phraseLabel=$('#confirmPhraseLabel');
  $('#confirmTitle').textContent=title; $('#confirmBody').textContent=body;
  $('#confirmWhy').textContent=why; $('#confirmWhy').hidden=!why;
  const needPhrase=!!phrase; phraseLabel.hidden=!needPhrase; input.value='';
  ok.textContent=danger?'Delete':'Confirm';
  const validate=() => { ok.disabled=needPhrase && input.value!==phrase; };
  validate();
  const cleanup=() => { ok.removeEventListener('click',onOK); input.removeEventListener('input',validate); dlg.removeEventListener('close',onClose); };
  const onOK=() => { cleanup(); resolve(true); dlg.close(); };
  const onClose=() => { cleanup(); resolve(false); };
  ok.addEventListener('click',onOK); input.addEventListener('input',validate); dlg.addEventListener('close',onClose);
  openDialog('#dlgConfirm'); (needPhrase?input:ok).focus?.();
 });
}

// askWarn is the confirmation prompt for a warn-class path (server 409 on an
// otherwise-allowed mkdir/rename): show the server's reason and the scan facts.
function askWarn(confirm,message) {
 const s=confirm.summary||{};
 return confirmDialog({title:'Confirm change',body:message||'This location needs confirmation.',why:(s.warnings||[]).join(' · ')});
}

// actionError maps a failure code to a plain-language message (§6).
function actionError(err) {
 const messages={
  read_only:'Read-only mode is on. Open Settings to turn it off before making changes.',
  protected:'That is a protected system path and cannot be changed here.',
  not_empty:'The folder is not empty. Deleting a folder’s contents is coming in a later version.',
  permission:'The system refused the change (permission denied).',
  exists:'A file or folder with that name already exists here.',
  cross_device:'The source and destination are on different volumes.',
 };
 error(new Error(messages[err.code] || err.message || 'The change could not be completed.'));
}

function afterMutation(message) {
 if (message) announce(message);
 loadList(); loadTree();
}

function currentDirArg() { return state.pathB64 ? {dirB64:state.pathB64} : {dir:state.path}; }

export async function newFolder() {
 if (!state.session?.canWrite) return;
 const name=await promptDialog({title:'New folder',label:'Folder name',value:''});
 if (name==null || name.trim()==='') return;
 const valid=sessionGuard();
 try {
  const res=await runMutation('api/fs/mkdir',{...currentDirArg(),name},askWarn);
  if (!valid()) return;
  if (res===null) return;
  afterMutation(`Created ${name}.`);
 } catch(err) { if (valid()) actionError(err); }
}

export async function renameEntry(entry) {
 const e=entry||focused();
 if (!e || !state.session?.canWrite) return;
 const name=await promptDialog({title:'Rename',label:'New name',value:e.name});
 if (name==null || name==='' || name===e.name) return;
 const valid=sessionGuard();
 try {
  const res=await runMutation('api/fs/rename',{...pathArgs(e),to:name},askWarn);
  if (!valid()) return;
  if (res===null) return;
  afterMutation(`Renamed to ${name}.`);
 } catch(err) { if (valid()) actionError(err); }
}

export async function deleteEntries(entries) {
 if (!state.session?.canWrite || !entries || !entries.length) return;
 const label=entries.length===1 ? `“${entries[0].name}”` : `${entries.length} items`;
 // Grade 1: a simple confirm before any request.
 if (!await confirmDialog({title:'Delete',body:`Delete ${label}? This cannot be undone.`,danger:true})) return;
 const body=entries.length===1 ? pathArgs(entries[0]) : {paths:entries.map(pathArgs)};
 const valid=sessionGuard();
 try {
  // Grade 2: the server may still demand a confirmation token for a warn area.
  const res=await runMutation('api/fs/delete',body,(confirm,message) =>
   confirmDialog({title:'Confirm deletion',body:message||'This location needs confirmation.',why:(confirm.summary?.warnings||[]).join(' · '),danger:true}));
  if (!valid()) return;
  if (res===null) return;
  if (res.results) {
   const failed=res.results.filter(r => !r.ok);
   if (failed.length) { error(new Error(`${res.results.length-failed.length} of ${res.results.length} deleted; ${failed.length} could not be (${failed.map(r => r.code).join(', ')}).`)); afterMutation(); return; }
  }
  afterMutation('Deleted.');
 } catch(err) { if (valid()) actionError(err); }
}

// deleteSelection deletes the current explicit selection (toolbar/keyboard).
export function deleteSelection() {
 const entries=selectedEntries();
 if (entries===null) { error(new Error('Select items individually to delete them in this version.')); return; }
 deleteEntries(entries);
}

export function initActions() {
 $('#btnMkdir').addEventListener('click',() => newFolder());
 $('#btnRename').addEventListener('click',() => renameEntry(focused()));
 $('#btnDelete').addEventListener('click',() => deleteSelection());
 // Context-menu entries, added without list.js importing this module.
 extraActions.push({label:'Rename…',show:() => !!state.session?.canWrite,run:e => renameEntry(e)});
 extraActions.push({label:'Delete',show:() => !!state.session?.canWrite,run:e => deleteEntries([e])});
}
