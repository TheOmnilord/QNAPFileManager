import {api} from './api.js';
import {$,el,error,announce,openDialog,pathArgs,toast} from './dom.js';
import {state,sessionGuard,listingActions,sessionTransition,subscribe} from './state.js';
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

// oneDialog runs exactly ONE dialog lifecycle and resolves only from the
// element's own `close` event.
//
// The distinction matters because `close` is ASYNCHRONOUS. `dlg.close()` clears
// .open synchronously and queues the event; a dialog that resolved its promise
// from the OK handler therefore released its caller — and, behind it, the
// confirmation queue — while its own close event was still in flight. The next
// question then set itself up, attached its listeners, and opened; and only
// then did the PREVIOUS close arrive, was delivered to the listeners that
// happened to be attached by then, and cancelled the new question. What was
// left on screen was an open, unresponsive modal (round 7, finding 1).
//
// So: `setup` paints and wires the dialog and is handed a `finish(answer)` that
// only records the answer and closes; the promise settles when the element has
// really shut and its event has been delivered. Anything waiting for the
// promise — the queue included — therefore starts from a quiet dialog.
//
// `dlg` needs only addEventListener/removeEventListener/.open/.close(), so the
// whole lifecycle is unit-testable against a fake whose close is async.
// It is also where an answer is bound to the PERSON WHO GAVE IT.
//
// The close event's asynchrony is a window, and a session switch fits inside
// it: OK recorded the answer and closed the dialog, the switch landed, and the
// close event then handed the departed user's answer to a caller that had not
// yet captured a session guard — newFolder, renameEntry and deleteEntries all
// capture theirs only after awaiting the dialog. Alice's folder name was
// created in Bob's directory, with Bob's CSRF token (round 9). The confirmation
// queue's ticket did not help: prompt and delete dialogs never go through it.
//
// Binding the check here covers all four dialogs at once, because this is the
// one place any of them can produce an answer.
export function oneDialog(dlg,setup,fallback=null) {
 return new Promise(resolve => {
  // Already open means someone else owns this element; refusing is the only
  // safe answer (the queue makes it unreachable for the dialogs it serialises).
  if (dlg.open) { resolve(fallback); return; }
  const ticket=confirmTicket(state.session,state.sessionGeneration);
  let answer=fallback,teardown=null;
  const onClose=() => {
   dlg.removeEventListener('close',onClose);
   teardown?.();
   // A refresh keeps the answer; a sign-out or a change of user discards it.
   resolve(confirmTicketValid(ticket,state.session) ? answer : fallback);
  };
  dlg.addEventListener('close',onClose);
  teardown=setup(value => { answer=value; dlg.close(); });
 });
}

// promptDialog resolves to the entered string, or null if cancelled.
function promptDialog({title,label,value=''}) {
 const dlg=$('#dlgPrompt'),input=$('#promptInput'),ok=$('#promptOK');
 return oneDialog(dlg,finish => {
  $('#promptTitle').textContent=title; $('#promptLabel').textContent=label; input.value=value;
  const onOK=() => finish(input.value);
  ok.addEventListener('click',onOK);
  openDialog('#dlgPrompt'); input.focus?.(); input.select?.();
  return () => ok.removeEventListener('click',onOK);
 },null);
}

// confirmQueue serialises everything that asks the user a modal question.
//
// There is ONE #dlgConfirm element and every caller re-dresses it. That is safe
// exactly as long as two callers never own it at once — and they did. Emptying
// the Trash is the canonical grade-2 action: it opens the dialog and waits for
// the word "empty" to be typed. A background upload hitting an overwrite then
// called confirmDialog too: it rewrote the title and the body, cleared the
// phrase requirement (its own question had none, so `ok.disabled` became
// false), and attached a SECOND click handler beside the one Trash was still
// waiting on. One click on OK resolved both promises — the Trash was emptied,
// permanently, without the phrase ever being typed, under a heading about an
// upload (round 6, finding 1).
//
// So questions are asked one at a time, in the order they were raised. A caller
// that arrives while another question is open waits for its turn rather than
// stealing the dialog.
//
// The rule for callers: never call confirmQueue from inside a queued function.
// Nothing does, and nothing may — it would wait for itself.
// A queued question also belongs to the SESSION that raised it, and that is not
// a detail — it is the difference between asking the right person and asking
// whoever happens to be sitting there.
//
// signInNotice() closes the dialog that is on screen. Its close event advanced
// the queue, which opened the NEXT question — one raised by the user who has
// just gone — under the new user's session. Approving it took the operation
// through runMutation, which reposted it with the NEW user's CSRF token; the
// session checks in newFolder and renameEntry run only after the request has
// already been sent. So a question nobody currently at the keyboard had asked
// for could be answered by them, as them (round 8).
//
// Every entry therefore carries a ticket taken at ENQUEUE, and the ticket is
// checked twice: when its turn comes, so a stale question never reaches the
// screen at all, and again when it is answered, so an approval cannot outlive
// the user who gave it. A switch or a sign-out also flushes the queue outright.
const confirmPending=new Set();

// confirmTicket is who is asking, captured before the question is raised.
export function confirmTicket(session,generation) {
 return {user:session?.user ?? null,uid:session?.uid ?? null,generation};
}

// confirmTicketValid says whether the person the question was raised for is
// still the person at the keyboard. A REFRESH keeps the ticket — the same user
// with a rotated token or a toggled setting is still the same user; only a
// sign-out or a change of user invalidates it.
export function confirmTicketValid(ticket,session) {
 return !!ticket && !!session && ticket.user===session.user && ticket.uid===session.uid;
}

// flushConfirmQueue disowns every question that has not yet been answered. It
// runs from the session subscriber BEFORE signInNotice() closes the dialogs, so
// no entry can be revived by the close event that follows.
export function flushConfirmQueue() { for (const entry of confirmPending) entry.flushed=true; }

let confirmChain=Promise.resolve();
export function confirmQueue(run,refused=false) {
 const entry={ticket:confirmTicket(state.session,state.sessionGeneration),flushed:false};
 confirmPending.add(entry);
 const owned = async () => {
  confirmPending.delete(entry);
  // Its turn has come: is the question still worth asking?
  if (entry.flushed || !confirmTicketValid(entry.ticket,state.session)) return refused;
  const answer=await run();
  // It was on screen while the world could change under it. An answer is only
  // an answer from the person who was asked.
  if (entry.flushed || !confirmTicketValid(entry.ticket,state.session)) return refused;
  return answer;
 };
 // `owned` on both settlements: the queue is about ORDER, not about whether the
 // previous question succeeded.
 const mine=confirmChain.then(owned,owned);
 // A rejection must not poison the queue for every question after it.
 confirmChain=mine.then(() => {},() => {});
 return mine;
}

// confirmDialog resolves to true only when confirmed. When phrase is set, the
// OK button stays disabled until the typed text matches it exactly. okLabel
// names the button for callers whose dangerous action is not a delete — an
// overwriting copy is danger-styled but says "Copy", not "Delete".
//
// It takes its turn in the queue above, so it always opens a dialog nobody else
// is answering.
export function confirmDialog(options) { return confirmQueue(() => askConfirm(options)); }

// askConfirm is one lifecycle of #dlgConfirm. The "already open" refusal that
// oneDialog performs is the same guarantee this used to make for itself: the
// queue makes it unreachable, and the failure it prevents — approving an
// operation the user never saw — is worth refusing over.
function askConfirm({title,body,why='',danger=false,phrase='',okLabel=''}) {
 const dlg=$('#dlgConfirm'),ok=$('#confirmOK'),input=$('#confirmPhrase'),phraseLabel=$('#confirmPhraseLabel');
 return oneDialog(dlg,finish => {
  $('#confirmTitle').textContent=title; $('#confirmBody').textContent=body;
  $('#confirmWhy').textContent=why; $('#confirmWhy').hidden=!why;
  const needPhrase=!!phrase; phraseLabel.hidden=!needPhrase; input.value='';
  $('#confirmPhraseName').textContent=phrase;
  ok.textContent=okLabel || (danger?'Delete':'Confirm');
  // The danger styling #dlgConfirm.danger already defines, now actually applied:
  // an overwriting copy destroys what is there and must not look routine.
  dlg.classList.toggle('danger',!!danger);
  const validate=() => { ok.disabled=needPhrase && input.value!==phrase; };
  validate();
  const onOK=() => finish(true);
  ok.addEventListener('click',onOK); input.addEventListener('input',validate);
  openDialog('#dlgConfirm'); (needPhrase?input:ok).focus?.();
  return () => { ok.removeEventListener('click',onOK); input.removeEventListener('input',validate); };
 },false);
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
  owner_unset:'The folder was created but could not be assigned to you; it is owned by the system — check it or delete it.',
  cross_device:'The source and destination are on different volumes.',
  invalid_target:'The destination is inside the folder being copied.',
  no_trash:'There is no Trash on this volume, so deleting here is permanent.',
  queue_full:'Too many operations are already queued. Wait for some to finish, then try again.',
  // M2-C. `conflict` is an upload finding something that is NOT a plain file
  // under the name it wanted (contract §1.3) — a distinct answer from `exists`,
  // which only an overwrite or a keep-both can resolve; nothing the conflict
  // dialog offers would help here, so it says what is actually in the way.
  conflict:'Something else — a folder or a link — already has that name here.',
  no_space:'There is not enough free space on the volume for this upload.',
  // M3. `unsupported` is the honest answer to an operation the system has no
  // way to perform on THIS object — Linux has no lchmod, so a symlink's own
  // mode cannot be changed at all; a chown of a link's target is refused
  // because lchown is the only chown M3 has (contract §1.4) — and to a route
  // to the inode that does not exist (a network mount, or a 0200 file with no
  // /proc). It is not a permission problem and must not read like one.
  unsupported:'The system cannot make that change to this kind of item. A symbolic link has no permissions of its own — change the item it points to instead.',
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

// onNewFolderError is newFolder's failure path, factored out so it is unit
// testable without a DOM (finding E). Whatever the error, it REFRESHES the
// listing first: mkdir can fail AFTER the folder was created — the root worker
// made it but could not chown it to the user (code owner_unset) or a concurrent
// change was detected — so the folder exists even though the request "failed".
// Refreshing makes that created-but-not-adopted folder visible rather than
// hidden behind an error (and a blind retry then hitting "already exists"). The
// deliberate no-rollback behaviour is kept: nothing is deleted here. Then the
// error is reported; actionMessage gives owner_unset its own clear sentence.
export function onNewFolderError(err,{refresh=()=>{ loadList(); loadTree(); },report=actionError}={}) {
 refresh();
 report(err);
}

export async function newFolder() {
 if (!state.session?.canWrite || !listingActions().mutate) return;
 // Captured BEFORE the dialog opens, not after it answers: the session can
 // change while the user is typing, and a guard taken afterwards belongs to
 // whoever is signed in by then (round 9). oneDialog refuses the answer
 // outright in that case; this is the second lock on the same door.
 const valid=sessionGuard();
 const name=await promptDialog({title:'New folder',label:'Folder name',value:''});
 if (!valid()) return;
 if (name==null || name.trim()==='') return;
 try {
  const res=await runMutation('api/fs/mkdir',{...currentDirArg(),name},askWarn);
  if (!valid()) return;
  if (res===null) return;
  afterMutation(`Created ${name}.`);
 } catch(err) { if (valid()) onNewFolderError(err); }
}

export async function renameEntry(entry) {
 const e=entry||focused();
 if (!e || !state.session?.canWrite) return;
 const valid=sessionGuard();   // before the dialog, as in newFolder
 const name=await promptDialog({title:'Rename',label:'New name',value:e.name});
 if (!valid()) return;
 if (name==null || name==='' || name===e.name) return;
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
// It runs through oneDialog for the same reason askConfirm does, and with more
// cause: deleteEntries RE-OPENS it in a loop when the server's summary raises
// the grade, so the next lifecycle begins microseconds after the last one
// closed — precisely the window in which a stray close event cancels the dialog
// that has just opened (round 7, finding 1).
function deleteDialog({entries,mode,summary,note}) {
 const dlg=$('#dlgDelete'),ok=$('#delOK'),perm=$('#delPermanent'),cross=$('#delCross'),phrase=$('#delPhrase');
 return oneDialog(dlg,finish => {
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
  const onOK=() => finish({mode:perm.checked ? 'permanent' : 'trash',crossMounts:!!cross.checked});
  ok.addEventListener('click',onOK); perm.addEventListener('change',paint); phrase.addEventListener('input',paint);
  paint();
  openDialog('#dlgDelete');
  (deleteGrade({mode:perm.checked ? 'permanent' : 'trash',summary})===2 ? phrase : ok).focus?.();
  return () => { ok.removeEventListener('click',onOK); perm.removeEventListener('change',paint); phrase.removeEventListener('input',paint); };
 },null);
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
 // One guard for the WHOLE operation, captured before the first dialog opens.
 // The loop re-opens the dialog when the server's summary raises the grade, and
 // every one of those openings belongs to the session that started the delete.
 const valid=sessionGuard();
 for (;;) {
  const choice=await deleteDialog({entries,mode,summary,note});
  if (!valid()) return;
  if (!choice) return;
  mode=choice.mode;
  // What the dialog just displayed, so a challenge that adds nothing new is not
  // shown a second time (and the loop cannot spin on the same warnings).
  const shownGrade=deleteGrade({mode,summary});
  for (const warning of summary?.warnings||[]) shown.add(warning);
  const body={paths:entries.map(pathArgs),mode,crossMounts:choice.crossMounts};
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
//
// A FAILED job is treated the same way as a cancelled one when it carries ids
// (finding R3-WA2). A delete that moved four of five entries and then hit a
// protected fifth ends "failed", but those four really are in Trash and the
// terminal result names them; discarding the ids because of the state left the
// user with a bare error and no way back short of hunting through the trash
// panel. So the partial outcome is described and the Undo is offered for what
// moved — safely, because /api/trash/restore re-validates every id against the
// caller's OWN trash listing before it dispatches anything.
export function trashOutcome(job,requested) {
 const count=value => Number(value||0).toLocaleString();
 if (!job) return {ids:[],message:`Still moving ${count(requested)} item(s) to Trash — see Operations.`};
 const ids=Array.isArray(job.result?.trashIds) ? job.result.trashIds : [];
 if (job.state==='failed') {
  if (!ids.length) return {ids:[],message:job.error||'The items could not be moved to Trash.'};
  const failed=Math.max(Number(requested||0)-ids.length,0);
  return {ids,message:`Moved ${count(ids.length)} of ${count(requested)} to Trash; ${count(failed)} failed`};
 }
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
 // The gate, enforced where the action IS and not only where its button is: a
 // Delete key must not reach a selection the search results are covering
 // (round 1, finding 1).
 if (!listingActions().mutate) return;
 let entries;
 try {
  entries=await selectionEntries();
 } catch(err) { error(err); return; }
 if (entries===null) { error(new Error('Select items individually to delete them in this version.')); return; }
 deleteEntries(entries);
}

export function initActions() {
 // The queue is disowned the moment the session stops being the same user's.
 // This subscriber fires from inside update(), which is the FIRST thing
 // signInNotice() does — before it closes the open dialogs — so every pending
 // question is already flushed by the time the close event advances the queue.
 let lastSession=state.session;
 subscribe(() => {
  const before=lastSession;
  lastSession=state.session;
  if (sessionTransition(before,state.session)!=='refresh') flushConfirmQueue();
 });
 $('#btnMkdir').addEventListener('click',() => newFolder());
 $('#btnRename').addEventListener('click',() => { const e=selectedOne(); if (e) renameEntry(e); });
 $('#btnDelete').addEventListener('click',() => deleteSelection());
 // Context-menu entries, added without list.js importing this module.
 extraActions.push({label:'Rename…',show:() => !!state.session?.canWrite,run:e => renameEntry(e)});
 extraActions.push({label:'Delete',show:() => !!state.session?.canWrite,run:e => deleteEntries([e])});
}
