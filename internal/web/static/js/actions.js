import {api} from './api.js';
import {$,el,error,announce,openDialog,pathArgs,toast} from './dom.js';
import {state,sessionGuard} from './state.js';
import {loadList,focused,selectedOne,selectionEntries,extraActions} from './list.js';
import {loadTree} from './tree.js';
import {trackJob,awaitJob,jobLive} from './jobs.js';

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
export function confirmDialog({title,body,why='',danger=false,phrase=''}) {
 return new Promise(resolve => {
  const dlg=$('#dlgConfirm'),ok=$('#confirmOK'),input=$('#confirmPhrase'),phraseLabel=$('#confirmPhraseLabel');
  $('#confirmTitle').textContent=title; $('#confirmBody').textContent=body;
  $('#confirmWhy').textContent=why; $('#confirmWhy').hidden=!why;
  const needPhrase=!!phrase; phraseLabel.hidden=!needPhrase; input.value='';
  $('#confirmPhraseName').textContent=phrase;
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

// actionMessage maps a failure to a plain-language message (§6). Pure, so it is
// unit-testable. A not-empty refusal still names what is inside — the M1
// single-level endpoint remains for API compatibility, and an "empty-looking"
// folder (usually hidden QNAP metadata like .@__thumb) should explain itself
// rather than look like a bug.
export function actionMessage(err) {
 const messages={
  read_only:'Read-only mode is on. Open Settings to turn it off before making changes.',
  protected:'That is a protected system path and cannot be changed here.',
  not_empty:'The folder is not empty. Use Delete, which removes a folder and its contents.',
  permission:'The system refused the change (permission denied).',
  exists:'A file or folder with that name already exists here.',
  cross_device:'The source and destination are on different volumes.',
  no_trash:'There is no Trash on this volume, so deleting here is permanent.',
  queue_full:'Too many operations are already queued. Wait for some to finish, then try again.',
 };
 if (err.code==='not_empty' && Array.isArray(err.blockers) && err.blockers.length){
  const names = err.blockers.map(b=>b.name).join(', ') + (err.truncated ? ', …' : '');
  const note = err.blockers.some(b=>b.hidden) ? ' These are hidden items — turn on Hidden to see them.' : '';
  return `The folder is not empty — still inside: ${names}.${note} Use Delete, which removes a folder and its contents.`;
 }
 return messages[err.code] || err.message || 'The change could not be completed.';
}

function actionError(err) { error(new Error(actionMessage(err))); }

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

// PERMANENT_WARNING is the exact sentence the server puts in a permanent
// delete's confirmation summary (web.permanentWarning). It is a pinned contract
// between the two halves: seeing it is what promotes the dialog to grade 2,
// whatever the client thought it was asking for.
export const PERMANENT_WARNING='This delete is permanent and cannot be undone.';

// deleteGrade is the confirmation ladder for a delete (ui-ux §4.2). Grade 1 is
// a simple confirm — a move to Trash is reversible. Grade 2 (typed phrase) is
// for anything irreversible: a permanent delete, a server summary that says so,
// a warn-class path, or a selection past the scale thresholds. Pure, so the
// rule is unit-tested rather than inferred from the DOM.
export function deleteGrade({mode,summary}) {
 const s=summary||{},warnings=s.warnings||[];
 if (mode==='permanent') return 2;
 if (warnings.includes(PERMANENT_WARNING)) return 2;
 if (warnings.length) return 2;
 if ((s.files||0)>100 || (s.bytes||0)>(1<<30)) return 2;
 return 1;
}

// deleteDialog is the one delete prompt: it chooses the mode, carries the
// crossing checkbox on QuTS hero, and is itself the grade-1 or grade-2
// confirmation. It resolves to {mode,crossMounts} or null.
function deleteDialog({entries,mode,summary,note}) {
 return new Promise(resolve => {
  const dlg=$('#dlgDelete'),ok=$('#delOK'),perm=$('#delPermanent'),cross=$('#delCross'),phrase=$('#delPhrase');
  const label=entries.length===1 ? `“${entries[0].name}”` : `${entries.length} items`;
  const hero=state.session?.family==='quts_hero';
  $('#delCrossRow').hidden=!hero;
  if (!hero) cross.checked=false;
  perm.checked=mode==='permanent';
  $('#delNote').textContent=note||''; $('#delNote').hidden=!note;
  const paint=() => {
   const current=perm.checked ? 'permanent' : 'trash';
   const grade=deleteGrade({mode:current,summary});
   const warnings=(summary?.warnings||[]).filter(warning => warning!==PERMANENT_WARNING);
   $('#delTitle').textContent=current==='permanent' ? 'Delete permanently' : 'Move to Trash';
   $('#delBody').textContent=current==='permanent'
    ? `Delete ${label} permanently? This cannot be undone.`
    : `Move ${label} to Trash?`;
   $('#delWhy').textContent=warnings.join(' · '); $('#delWhy').hidden=!warnings.length;
   const needPhrase=grade===2;
   $('#delPhraseLabel').hidden=!needPhrase;
   $('#delPhraseName').textContent=entries[0].name;
   dlg.classList.toggle('danger',needPhrase);
   ok.textContent=current==='permanent' ? 'Delete permanently' : 'Move to Trash';
   ok.disabled=needPhrase && phrase.value!==entries[0].name;
  };
  phrase.value='';
  const cleanup=() => { ok.removeEventListener('click',onOK); perm.removeEventListener('change',paint); phrase.removeEventListener('input',paint); dlg.removeEventListener('close',onClose); };
  const onOK=() => { cleanup(); const answer={mode:perm.checked ? 'permanent' : 'trash',crossMounts:!!cross.checked}; dlg.close(); resolve(answer); };
  const onClose=() => { cleanup(); resolve(null); };
  ok.addEventListener('click',onOK); perm.addEventListener('change',paint); phrase.addEventListener('input',paint); dlg.addEventListener('close',onClose);
  paint();
  openDialog('#dlgDelete');
  (deleteGrade({mode:perm.checked ? 'permanent' : 'trash',summary})===2 ? phrase : ok).focus?.();
 });
}

// deleteEntries deletes ANY selection — folders included, which is what the job
// spine adds over M1's single-level /api/fs/delete (kept for compatibility, no
// longer used here). The server demands a redeemed confirmation token for both
// modes (decision 10), so the flow is: ask, POST, take the token challenge back
// with the server's real summary, and re-post.
export async function deleteEntries(entries) {
 if (!state.session?.canWrite || !entries || !entries.length) return;
 let mode='trash',note='',summary=null;
 const shown=new Set();
 for (;;) {
  const choice=await deleteDialog({entries,mode,summary,note});
  if (!choice) return;
  mode=choice.mode;
  // What the dialog just displayed, so a challenge that adds nothing new is not
  // shown a second time (and the loop cannot spin on the same warnings).
  const shownGrade=deleteGrade({mode,summary});
  for (const warning of summary?.warnings||[]) shown.add(warning);
  const body={paths:entries.map(pathArgs),mode,crossMounts:choice.crossMounts};
  const valid=sessionGuard();
  try {
   // The dialog just shown IS the confirmation, so a challenge whose summary
   // holds nothing the dialog did not already cover is approved directly; a
   // summary that raises the grade re-opens the dialog with the server's own
   // reasons before the token is spent.
   let reAsk=false;
   const res=await runMutation('api/jobs/delete',body,async confirm => {
    const s=confirm.summary||{};
    const unseen=(s.warnings||[]).filter(warning => warning!==PERMANENT_WARNING && !shown.has(warning));
    if (!unseen.length && deleteGrade({mode,summary:s})<=shownGrade) return true;
    summary=s; reAsk=true; return false;
   });
   if (!valid()) return;
   if (reAsk) continue;
   if (res===null) return;
   trackJob(res.job);
   // The 202 says the work was ACCEPTED, not done — the job may still be queued
   // behind others — so what is said here is neutral. The success toast, and
   // with it the Undo, waits for the job's terminal state (finding W9).
   announce(mode==='permanent'
    ? `Deleting ${entries.length.toLocaleString()} item(s)…`
    : `Moving ${entries.length.toLocaleString()} item(s) to Trash…`);
   if (mode!=='permanent') undoWhenDone(res.job,entries.length);
   return;
  } catch(err) {
   if (!valid()) return;
   if (err.code==='no_trash') {
    // §4.4: never silently promoted. The dialog re-opens as a permanent delete
    // and says why it had to.
    mode='permanent'; summary=null;
    note='No Trash is available on this volume, so this delete is permanent.';
    continue;
   }
   actionError(err); return;
  }
 }
}

// trashOutcome is what a finished delete-to-trash is worth saying, and what it
// can offer to undo. Pure, so the wording and the "no ids, no Undo" rule are
// unit-tested rather than inferred from the DOM (finding W9).
//
// The ids are the job's own: the worker names the trash entries it created and
// they reach here as result.trashIds, so an Undo restores exactly what THIS
// delete moved rather than whatever the trash panel currently holds under the
// same original path. A cancelled job reports what it managed before it stopped
// — nothing is rolled back (design §3) — and no ids at all means there is
// nothing this toast can honestly offer to reverse; the trash panel is then the
// answer.
export function trashOutcome(job,requested) {
 const count=value => Number(value||0).toLocaleString();
 if (!job) return {ids:[],message:`Still moving ${count(requested)} item(s) to Trash — see Operations.`};
 const ids=Array.isArray(job.result?.trashIds) ? job.result.trashIds : [];
 if (job.state==='failed') return {ids:[],message:job.error||'The items could not be moved to Trash.'};
 if (job.state==='cancelled') {
  return {ids,message: ids.length
   ? `Cancelled — ${count(ids.length)} of ${count(requested)} item(s) reached Trash`
   : `Cancelled — nothing was moved to Trash`};
 }
 if (!ids.length) return {ids,message:`Moved ${count(requested)} item(s) to Trash`};
 return {ids,message:`Moved ${count(ids.length)} item(s) to Trash`};
}

// undoRestore posts the Undo and returns the restore job. It touches no DOM, so
// the request itself is unit-testable; runUndo is the part that paints.
export async function undoRestore(ids) {
 const res=await api('api/trash/restore',{},{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids})});
 return res.job;
}

function runUndo(ids) {
 const valid=sessionGuard();
 undoRestore(ids).then(job => { if (valid()) trackJob(job); }).catch(err => { if (valid()) actionError(err); });
}

// undoWhenDone offers the 15-second Undo of ui-ux §4.4 — but only once the job
// has actually finished (finding W9). Offering it at the 202 meant the window
// could expire while the job was still queued, and a click in the meantime
// found no ids and reported an error; now the toast appears with the real
// count, the real ids and a full 15 seconds to act on them.
async function undoWhenDone(job,requested) {
 const valid=sessionGuard();
 try {
  const final=jobLive(job) ? await awaitJob(job.id) : job;
  if (!valid()) return;
  const {ids,message}=trashOutcome(final,requested);
  if (!ids.length) { announce(message); return; }
  toast(message,'Undo',() => runUndo(ids),15000);
 } catch(err) { if (valid()) actionError(err); }
}

// deleteSelection deletes the current explicit selection (toolbar/keyboard). It
// resolves the selection through selectionEntries, which fetches any selected
// pages that were never loaded, so a Shift-range spanning unloaded pages is
// deleted in full or not at all — never a silently truncated subset reported as
// success (standard P2).
export async function deleteSelection() {
 let entries;
 try {
  entries=await selectionEntries();
 } catch(err) { error(err); return; }
 if (entries===null) { error(new Error('Select items individually to delete them in this version.')); return; }
 deleteEntries(entries);
}

export function initActions() {
 $('#btnMkdir').addEventListener('click',() => newFolder());
 $('#btnRename').addEventListener('click',() => { const e=selectedOne(); if (e) renameEntry(e); });
 $('#btnDelete').addEventListener('click',() => deleteSelection());
 // Context-menu entries, added without list.js importing this module.
 extraActions.push({label:'Rename…',show:() => !!state.session?.canWrite,run:e => renameEntry(e)});
 extraActions.push({label:'Delete',show:() => !!state.session?.canWrite,run:e => deleteEntries([e])});
}
