import {apiURL,signInNotice} from './api.js';
import {$,announce,error,openDialog} from './dom.js';
import {state,subscribe,sameSession,listingActions} from './state.js';
import {actionMessage,confirmDialog,confirmQueue,oneDialog} from './actions.js';
import {addLocalJob,dropLocalJob,hasLocalJob,localJobs,repaintJobs,updateLocalJob,showJobsPanel} from './jobs.js';
import {loadList} from './list.js';
import {loadTree} from './tree.js';

// Upload (M2-C, contract §1.5). One file per request, one request at a time:
// POST /api/fs/upload with the file as the raw body. XMLHttpRequest rather than
// fetch, for one reason only — fetch cannot report UPLOAD progress, and an
// upload with no progress on a NAS link is indistinguishable from a hang.
//
// Everything above the "--- queue" line is pure: the URL, the queue order, the
// merge with the server's jobs, the conflict arithmetic and the percentage are
// all unit-tested (internal/web/upload_test.mjs) rather than eyeballed through a
// browser, because each of them has exactly one way to be subtly wrong.

// CONFLICTS are the policies the route accepts. Anything else is a bug on this
// side, and skip — the policy that destroys nothing — is what a bug degrades to.
export const CONFLICTS=['skip','overwrite','rename'];

// UPLOAD_NOTICES is the same pin TRANSFER_NOTICES is, for the same reason.
//
// An upload's confirm summary mixes two kinds of sentence. The ROUTE writes
// about the operation itself — today exactly one, the overwrite notice, shared
// verbatim with the transfer route — and that is grade L1: loud, not dangerous.
// The GUARD contributes protection reasons, which are free-form rule text and
// are grade L2, the typed phrase (contract §1.4: "protected is L2 via the
// ladder"). The wire carries no flag saying which is which, so the route's own
// sentences are PINNED here and anything else in the list is taken to be a
// guard reason.
//
// Without this every warn-class destination — /etc/config is the one that
// matters, since that is firmware configuration — reached a plain one-click
// confirm (round 2, finding 2). These strings are a contract with
// internal/web/routes_upload.go and are held to it by
// TestUploadNoticesArePinnedToTheClient.
export const UPLOAD_NOTICES=[
 'Existing files may be overwritten by this operation.',
];

// uploadGrade is the confirmation ladder for one upload. Grade 1 is a plain
// confirm; grade 2 demands the file's name typed out, exactly as the delete
// dialog does, and is reached by any summary line the route did not write.
export function uploadGrade(summary) {
 return ((summary||{}).warnings||[]).some(warning => !UPLOAD_NOTICES.includes(String(warning))) ? 2 : 1;
}

// uploadQueueOrder is the queue: the files in the order the user chose them,
// unchanged. A FileList is not an Array (no shift, no spread into a stable
// copy), and the picker's order IS the user's intent, so this only materialises
// it and drops anything that is not a file. It must stay STABLE — sorting by
// size or name would upload a batch in an order nobody asked for, which matters
// the moment one of them fails and the user has to reason about what got there.
export function uploadQueueOrder(files) {
 return [...(files||[])].filter(file => file && typeof file.name==='string');
}

// uploadURL builds the request URL. The directory travels in the SAME two
// spellings every other path does: dirB64 when the folder has authoritative
// bytes (a name that is not valid UTF-8 has no other honest spelling), dir
// otherwise. size and mtime are declared so the worker can refuse early for
// want of space and can stamp the file with the time it had on the client.
//
// `confirm` is a QUERY parameter here, not a body field as in every other
// mutation: the body IS the file, so there is nowhere else to put it.
export function uploadURL(dir,file,policy,token) {
 const d=dir||{},f=file||{};
 const params=d.pathB64 ? {dirB64:d.pathB64} : {dir:String(d.path??'')};
 params.name=String(f.name??'');
 const size=Number(f.size);
 if (Number.isFinite(size) && size>=0) params.size=String(Math.floor(size));
 // lastModified is milliseconds; the wire wants whole seconds. A file with no
 // timestamp (0, or a browser that withholds it) says nothing rather than
 // claiming 1970.
 const mtime=Math.floor(Number(f.lastModified??0)/1000);
 if (Number.isFinite(mtime) && mtime>0) params.mtime=String(mtime);
 params.conflict=CONFLICTS.includes(policy) ? policy : 'skip';
 if (token) params.confirm=String(token);
 return apiURL('api/fs/upload',params);
}

// progressOf is the percentage for one file, or null when there is no honest
// denominator (an unknown or zero length). null means INDETERMINATE — the same
// contract jobPercent has with the progress bar — and is never rounded to 0 or
// 100, both of which would be a claim.
export function progressOf(loaded,total) {
 const l=Number(loaded),t=Number(total);
 if (!Number.isFinite(t) || t<=0) return null;
 if (!Number.isFinite(l) || l<0) return 0;
 return Math.max(0,Math.min(100,Math.round(l/t*100)));
}

// mergeJobs is what the Operations panel actually lists: this tab's own upload
// entries followed by the server's jobs.
//
// Two rules, and both are about identity. Local entries come FIRST because they
// are the only ones the user just started and cannot see anywhere else. And the
// SERVER wins any id collision: a local id is a local invention ("upload-3")
// and can never legitimately name a server job, so a collision means something
// is wrong and the authoritative record is the one that survives. Order within
// each half is preserved exactly — the panel must not reshuffle under a poll.
export function mergeJobs(server,local) {
 const list=(Array.isArray(server) ? server : []).filter(Boolean);
 const ids=new Set(list.map(job => job.id));
 const mine=(Array.isArray(local) ? local : []).filter(job => job && !ids.has(job.id));
 return [...mine,...list];
}

// conflictDecision is the arithmetic behind "‘x’ already exists": what was
// chosen, whether it becomes the batch's standing policy, and how many files
// the one click just answered for.
//
// A dismissed dialog (no policy) is a CANCELLATION of that file, not a silent
// skip: the difference is visible in the panel, and "apply to all" is ignored
// for it — dismissing a question must never set a policy for files nobody was
// asked about.
export function conflictDecision(policy,applyAll,remaining) {
 const left=Math.max(0,Math.floor(Number(remaining))||0);
 if (!CONFLICTS.includes(policy)) return {policy:null,cancelled:true,remember:false,applies:0};
 return {policy,cancelled:false,remember:!!applyAll,applies:applyAll ? 1+left : 1};
}

// uploadError reads one XHR response the way api.js reads a fetch: a success
// carries the parsed body, a failure an Error with the server's .code and, for
// a 409 confirm_required, its .confirm. XHR has no json() and no ok, so this is
// the seam where the two halves are made to speak the same language — and it is
// pure, so every status the route can answer is covered by a test rather than
// by trying to provoke it from a browser.
export function uploadError(status,text) {
 let data=null;
 try { data=JSON.parse(text); } catch { /* a proxy may answer HTML */ }
 if (status>=200 && status<300) return {data:data??{}};
 const message=[data?.error?.message,data?.error?.path].filter(Boolean).join(' — ') || `Request failed (${status})`;
 return {error:Object.assign(new Error(message),{status,code:data?.error?.code,confirm:data?.confirm})};
}

// The upload route admits four uploads per session and thirty-two across the
// process, and answers 429 queue_full when they are all taken. This tab's queue
// is sequential, so one tab alone will not fill them — several tabs, or several
// devices on the same account, will.
//
// A 429 is not a failure: it is "not now". The file has not been refused, the
// destination has not been judged, nothing has been written — the only correct
// response is to wait and ask again. So the entry stays QUEUED, says what it is
// waiting for, and retries the same file unchanged.
export const UPLOAD_RETRY_BASE=1000;    // the first wait
export const UPLOAD_RETRY_CAP=30000;    // no single wait is longer than this
export const UPLOAD_RETRY_BUDGET=120000; // and no file waits longer than this in total

// uploadRetryDelay is the back-off schedule: 1 s, 2 s, 4 s, 8 s, 16 s, then 30 s
// for ever after. Doubling keeps a short-lived crowd cheap (most waits are the
// first one) and the cap keeps a long-lived one from becoming indistinguishable
// from a hang.
export function uploadRetryDelay(attempt) {
 const n=Math.max(0,Math.floor(Number(attempt)) || 0);
 // 2**n overflows to Infinity long before it matters; Math.min still caps it.
 return Math.min(UPLOAD_RETRY_CAP,UPLOAD_RETRY_BASE*2**n);
}

// uploadWaitPlan is the whole decision a 429 needs: how long to wait, or that
// the file has waited long enough. Giving up is a real outcome — two minutes of
// a full queue means something is wrong elsewhere, and a file that waits for
// ever is a file nobody is told about.
export function uploadWaitPlan(attempt,waited) {
 const spent=Math.max(0,Number(waited) || 0);
 if (spent >= UPLOAD_RETRY_BUDGET) return {wait:0,giveUp:true};
 return {wait:uploadRetryDelay(attempt),giveUp:false};
}

// isBusy recognises the route's "not now" in both of its spellings.
const isBusy = err => err?.code==='queue_full' || err?.status===429;

// isFolderDrop decides whether a dropped item is a DIRECTORY, which this
// version refuses. The entry API is the authority where the browser offers it
// (webkitGetAsEntry().isDirectory); where it does not, the heuristic is the
// only signal there is — a dropped folder arrives as a File of size 0 with no
// type. That heuristic also catches a genuinely empty, extension-less file,
// which is why the entry is consulted FIRST and the heuristic only fills in.
export function isFolderDrop(entry,file) {
 if (entry && typeof entry.isDirectory==='boolean') return entry.isDirectory;
 return !!file && Number(file.size)===0 && !file.type;
}

export const FOLDER_REFUSAL='Folders cannot be uploaded yet — select the files inside them.';

// --- queue -------------------------------------------------------------------

// The queue is strictly sequential: one XHR in flight, so a batch of large
// files cannot saturate the NAS link or the worker's descriptor budget, and the
// progress the panel shows is progress that is actually being made.
let queue=[],running=false,batchPolicy=null,serial=0;
// batch is bumped by teardown. Every local job records the batch it was made
// in, and no continuation from an older batch may touch the panel again — see
// jobStillOwned.
let batch=0;

// jobStillOwned says whether a continuation may still write to this entry.
//
// An upload's continuations are asynchronous and outlive their own teardown: a
// session ending aborts the XHR and removes the entry, and the abort's
// rejection lands a moment LATER, in a catch that dutifully "finished" the job
// — re-inserting the entry that had just been removed, with the previous user's
// file name in its title, for the next person to see in the same tab.
//
// Two conditions, both necessary. The entry must belong to the CURRENT batch,
// which teardown invalidates wholesale; and it must still be PRESENT, because
// "Clear finished" removes entries too and a late progress event must not bring
// one back. Pure, so "a completion after teardown inserts nothing" is a test.
export function jobStillOwned(job,current,present) {
 return !!job && job.batch===current && !!present;
}

// paintSoon coalesces repaints. upload.onprogress fires far faster than the
// panel needs to be rebuilt, and renderJobs replaces every row; at 200 ms the
// bar still moves smoothly and the DOM is not thrashed.
let paintedAt=0,paintTimer=null;
function paintSoon() {
 const now=Date.now();
 if (now-paintedAt>=200) { paintedAt=now; repaintJobs(); return; }
 if (paintTimer===null) paintTimer=setTimeout(() => { paintTimer=null; paintedAt=Date.now(); repaintJobs(); },200);
}

// A local job is shaped exactly like a server job so jobRow, jobDetailLine and
// jobLive need no special case; `local` marks it, and `cancel` is its own Cancel
// (there is no server-side id to POST to).
function makeJob(file) {
 const job={
  id:`upload-${++serial}`,local:true,batch,kind:'upload',title:`Uploading: ${file.name}`,
  state:'queued',files:0,filesTotal:1,bytes:0,bytesTotal:Number(file.size)||0,
  percent:null,rate:0,eta:-1,current:'',note:'',error:'',warningCount:0,
 };
 job.cancel=() => cancelLocal(job);
 addLocalJob(job);   // the ONLY insertion; everything after this only updates
 return job;
}

// Every write to an entry passes the ownership check, so a continuation that
// outlived its teardown mutates a detached object and touches nothing the user
// can see.
function setJob(job,patch) {
 if (!jobStillOwned(job,batch,hasLocalJob(job?.id))) return;
 Object.assign(job,patch);
 updateLocalJob(job);
}

function finishJob(job,jobState,note) {
 if (job) job.xhr=null;
 if (!jobStillOwned(job,batch,hasLocalJob(job?.id))) return;
 setJob(job,{state:jobState,note:note||'',rate:0,eta:-1,current:'',files:jobState==='done' ? 1 : 0,
  percent:jobState==='done' ? 100 : job.percent});
 repaintJobs();
}

// cancelAction says how a Cancel reaches this job. The order is the fix: a job
// WAITING out a back-off is woken, whatever else it may still be carrying — the
// thing to interrupt is the timer, not a transport that has already finished.
// Pure, so the precedence is a test rather than a sequence of ifs to re-read.
export function cancelAction(job) {
 if (!job || job.state==='done' || job.state==='failed' || job.state==='cancelled') return 'none';
 if (job.wake) return 'wake';    // waiting for a free slot
 if (job.xhr) return 'abort';    // a request really is in flight
 return 'finish';                // queued, never started
}

function cancelLocal(job) {
 const how=cancelAction(job);
 if (how==='none') return;
 job.cancelled=true;
 // Waking lets uploadOne's post-wait check finish the job; aborting lands in
 // the 'abort' handler and does the same; a job that never started is finished
 // here, and runQueue skips it when its turn comes.
 if (how==='wake') job.wake();
 else if (how==='abort') job.xhr.abort();
 else finishJob(job,'cancelled','Cancelled before it started.');
 repaintJobs();
}

// waitForSlot sleeps between attempts, but wakes early for a cancel or a
// teardown: a user who presses Cancel must not watch a thirty-second timer run
// out first.
export function waitForSlot(job,ms) {
 return new Promise(resolve => {
  const done=() => { clearTimeout(timer); job.wake=null; resolve(); };
  const timer=setTimeout(done,ms);
  job.wake=done;
 });
}

// send streams one file. The request context on the server side turns a client
// disconnect into a Discard (contract §1.4), so an abort here really does leave
// nothing behind.
function send(file,dir,policy,token,job) {
 return new Promise((resolve,reject) => {
  const xhr=new XMLHttpRequest();
  job.xhr=xhr;
  xhr.open('POST',uploadURL(dir,file,policy,token),true);
  // The same three-lock CSRF scheme every mutation uses; it does not depend on
  // the content type (contract §1.1).
  if (state.session?.csrf) xhr.setRequestHeader('X-QFM-CSRF',state.session.csrf);
  xhr.setRequestHeader('Content-Type','application/octet-stream');
  const started=Date.now();
  xhr.upload.addEventListener('progress',ev => {
   const total=ev.lengthComputable ? ev.total : Number(file.size)||0;
   const seconds=(Date.now()-started)/1000;
   setJob(job,{bytes:ev.loaded,bytesTotal:total,percent:progressOf(ev.loaded,total),
    rate:seconds>0.5 ? ev.loaded/seconds : 0,
    eta:seconds>0.5 && ev.loaded>0 && total>ev.loaded ? (total-ev.loaded)/(ev.loaded/seconds) : -1});
   paintSoon();
  });
  // A FINISHED request is not this job's transport any more. Leaving it on the
  // job meant Cancel found an xhr, called abort() on an already-DONE request —
  // which dispatches nothing, by specification — and then sat through the whole
  // back-off wait, blocking every file behind it (round 10). Every exit clears
  // it, so `job.xhr` only ever means "a request is in flight".
  const settle=fn => (...args) => { if (job.xhr===xhr) job.xhr=null; fn(...args); };
  xhr.addEventListener('load',settle(() => {
   const {data,error:err}=uploadError(xhr.status,xhr.responseText||'');
   // 401 ends the session everywhere else in the app; an upload must not be the
   // one place that quietly reports "Request failed (401)".
   if (xhr.status===401) signInNotice();
   if (err) reject(err); else resolve(data);
  }));
  xhr.addEventListener('error',settle(() => reject(Object.assign(new Error('Cannot reach the QNAPFileManager service — is it still running?'),{network:true}))));
  xhr.addEventListener('timeout',settle(() => reject(new Error('The upload timed out.'))));
  xhr.addEventListener('abort',settle(() => reject(Object.assign(new Error('Upload cancelled.'),{aborted:true}))));
  xhr.send(file);
 });
}

// askConflict is the per-batch "‘x’ already exists" dialog. It resolves to a
// conflictDecision, so the "apply to all remaining" arithmetic is the tested
// function's and not the dialog's.
//
// It takes its turn in the same queue confirmDialog uses. Both of an upload's
// questions are raised by a BACKGROUND queue rather than by a gesture the user
// just made, so they are the ones that can arrive while the user is in the
// middle of answering something else — which is exactly the collision the queue
// exists to prevent (finding 1). The dialogs a direct gesture opens (delete,
// prompt) cannot overlap anything and are left alone.
// The refusal value is a well-formed decision, not a bare false: a question the
// queue disowns (a session switch, round 8) must answer in the vocabulary the
// caller speaks, and "cancelled" is the answer that does nothing.
const askConflict = (name,remaining) =>
 confirmQueue(() => conflictDialog(name,remaining),conflictDecision(null,false,remaining));

function conflictDialog(name,remaining) {
 const dlg=$('#dlgUpConflict'),more=Math.max(0,Number(remaining)||0);
 // Everything resolves through 'close', dismissal included: a dialog closed
 // with Escape is a cancellation of THIS file and must answer the promise, or
 // the queue would stop forever on a keypress. oneDialog makes that the only
 // way it can resolve, and holds the queue until the element has really shut.
 return oneDialog(dlg,finish => {
  $('#upConflictBody').textContent=`“${name}” already exists in this folder.`;
  $('#upConflictMore').textContent=more ? `${more.toLocaleString()} more file(s) are waiting in this batch.` : '';
  $('#upConflictMore').hidden=!more;
  $('#upAll').checked=false;
  $('#upAllRow').hidden=!more;
  const buttons=[['#upSkip','skip'],['#upOverwrite','overwrite'],['#upRename','rename']];
  // The "apply to all" box is read at CLOSE time, so a change made after the
  // policy button was pressed cannot be missed — the answer is the whole form.
  const handlers=buttons.map(([selector,value]) => [selector,() => finish(conflictDecision(value,$('#upAll').checked,more))]);
  for (const [selector,fn] of handlers) $(selector).addEventListener('click',fn);
  openDialog('#dlgUpConflict');
  $('#upSkip').focus?.();
  return () => { for (const [selector,fn] of handlers) $(selector).removeEventListener('click',fn); };
 },conflictDecision(null,false,more));
}

// uploadOne drives one file through at most three sends: the first attempt, a
// re-send under a conflict policy the user chose, and a re-send carrying the
// confirmation token an overwrite needs (overwrite is L1, contract §1.4).
// It returns true only when a file really landed, which is what decides whether
// the listing is worth reloading at the end.
// A 429 is counted SEPARATELY from those: waiting for a free slot is not a
// change of mind about the request, so it may happen many times without
// consuming the three transitions a file is allowed.
async function uploadOne(file,dir,job,live) {
 let policy=batchPolicy || 'skip',token='',transitions=0,busyAttempt=0,waited=0;
 for (;;) {
  if (transitions>3) { finishJob(job,'failed','The upload could not be completed.'); return false; }
  if (job.cancelled) { finishJob(job,'cancelled','Cancelled.'); return false; }
  // A re-send under a new policy, or with a confirmation token, starts the
  // bytes again from zero: the previous attempt's progress was not progress.
  setJob(job,{state:'running',bytes:0,percent:null,note:'',error:'',current:file.name});
  repaintJobs();
  try {
   const res=await send(file,dir,policy,token,job);
   if (!live()) { finishJob(job,'cancelled','The session ended.'); return false; }
   setJob(job,{bytes:job.bytesTotal});
   finishJob(job,'done',res?.path ? `Uploaded to ${res.path}` : 'Uploaded.');
   return true;
  } catch(err) {
   if (!live()) { finishJob(job,'cancelled','The session ended.'); return false; }
   if (err.aborted || job.cancelled) { finishJob(job,'cancelled','Cancelled.'); return false; }
   // "Not now": every admission slot is taken. Nothing has been written and
   // nothing has been judged, so the file waits and asks again, unchanged.
   if (isBusy(err)) {
    const plan=uploadWaitPlan(busyAttempt,waited);
    if (plan.giveUp) { finishJob(job,'failed','No upload slot became free after two minutes. Try again shortly.'); return false; }
    setJob(job,{state:'queued',bytes:0,percent:null,rate:0,eta:-1,current:'',
     note:`Waiting for a free upload slot — retrying in ${Math.round(plan.wait/1000)} s…`});
    repaintJobs();
    await waitForSlot(job,plan.wait);
    waited+=plan.wait; busyAttempt++;
    if (!live()) { finishJob(job,'cancelled','The session ended.'); return false; }
    if (job.cancelled) { finishJob(job,'cancelled','Cancelled.'); return false; }
    continue;   // deliberately NOT a transition: the request is unchanged
   }
   if (err.code==='confirm_required' && err.confirm?.token) {
    const summary=err.confirm.summary||{};
    const grade=uploadGrade(summary);
    const approved=await confirmDialog({
     title:'Confirm upload',
     body:err.message||`Upload “${file.name}” to ${dir.path}?`,
     why:(summary.warnings||[]).join(' · '),
     // An overwrite destroys what is already there; a guard reason means the
     // destination itself is protected, and that is what the typed name is for.
     danger:policy==='overwrite' || grade===2,
     phrase:grade===2 ? file.name : '',
     okLabel:'Upload',
    });
    if (!live()) { finishJob(job,'cancelled','The session ended.'); return false; }
    if (!approved) { finishJob(job,'cancelled','Not confirmed.'); return false; }
    token=err.confirm.token;
    transitions++;
    continue;
   }
   if (err.code==='exists') {
    // A standing batch policy answers without asking again; only the FIRST
    // conflict of a batch is a question.
    const decision=batchPolicy
     ? {policy:batchPolicy,cancelled:false,remember:false}
     : await askConflict(file.name,queue.length);
    if (!live()) { finishJob(job,'cancelled','The session ended.'); return false; }
    if (decision.remember) batchPolicy=decision.policy;
    if (decision.cancelled) { finishJob(job,'cancelled','Cancelled.'); return false; }
    if (decision.policy==='skip') { finishJob(job,'done','Skipped — a file with that name is already there.'); return false; }
    policy=decision.policy;
    token='';   // a token is issued for the request that asked for it
    transitions++;
    continue;
   }
   finishJob(job,'failed',actionMessage(err));
   return false;
  }
 }
}

// runQueue is the single consumer. It exists once: uploadFiles only starts it
// when it is not already running, so two pickers or a picker and a drop share
// one queue rather than racing two.
async function runQueue() {
 running=true;
 // A batch belongs to the USER who started it, not to the session OBJECT that
 // was current when it started: a read-only toggle or the once-a-minute session
 // poll replaces that object, and an upload guarded by sessionGuard() was
 // abandoned by both (finding 2). sameSession is the predicate that answers the
 // question an upload actually has.
 const owner=state.session;
 const live=() => sameSession(owner,state.session);
 let landed=false;
 try {
  while (queue.length) {
   const item=queue.shift();
   if (item.job.cancelled) { finishJob(item.job,'cancelled','Cancelled before it started.'); continue; }
   if (!live()) { finishJob(item.job,'cancelled','The session ended.'); continue; }
   if (await uploadOne(item.file,item.dir,item.job,live)) landed=true;
  }
 } finally {
  running=false;
  batchPolicy=null;
  // Nothing may be left saying "running". A local entry is this tab's own
  // record and no poll will ever finish it, so a path that returned without
  // finishing one would have left it spinning for the rest of the session.
  for (const job of [...localJobs]) {
   if (job.local && (job.state==='queued' || job.state==='running')) finishJob(job,'cancelled','Stopped.');
  }
  repaintJobs();
 }
 // One refresh for the whole batch, and only when something actually arrived
 // (contract §1.5, and the REFRESH_KINDS rule jobs.js applies to server jobs).
 if (landed && live()) { announce('Upload finished.'); loadList(); loadTree(); }
}

// uploadFiles is the one entry point: the picker and the drop both land here.
// The destination is captured NOW, so a batch started in /share/Photos keeps
// uploading there even if the user browses away while it runs.
export function uploadFiles(files,dir) {
 if (!state.session?.canWrite) { error(new Error('Read-only mode is on. Open Settings to turn it off before uploading.')); return; }
 // The destination is the folder the LISTING is showing, so an upload started
 // while the search results cover it would land somewhere the user is not
 // looking (round 1, finding 1).
 if (!listingActions().mutate) { error(new Error('Close the search results (Esc) to upload into this folder.')); return; }
 const list=uploadQueueOrder(files);
 if (!list.length) return;
 const target=dir && (dir.path || dir.pathB64) ? {path:dir.path,pathB64:dir.pathB64} : {path:state.path,pathB64:state.pathB64};
 for (const file of list) queue.push({file,dir:target,job:makeJob(file)});
 showJobsPanel();
 repaintJobs();
 announce(`Queued ${list.length.toLocaleString()} file(s) for upload to ${target.path}.`);
 if (!running) runQueue().catch(err => error(err));
}

// --- drop target -------------------------------------------------------------

// The document-level suppressor in app.js stays: a file dropped anywhere else
// must not navigate the QTS desktop away from the app. The list pane is the one
// place that accepts a drop, and it stops propagation so the suppressor never
// sees it.
function dropItems(transfer) {
 const files=[],folders=[];
 const items=transfer?.items ? [...transfer.items] : [];
 const dropped=transfer?.files ? [...transfer.files] : [];
 if (items.length) {
  items.forEach((item,index) => {
   if (item.kind!=='file') return;
   const entry=item.webkitGetAsEntry?.() ?? null;
   const file=item.getAsFile?.() ?? dropped[index] ?? null;
   if (!file) return;
   if (isFolderDrop(entry,file)) folders.push(file.name); else files.push(file);
  });
  return {files,folders};
 }
 for (const file of dropped) {
  if (isFolderDrop(null,file)) folders.push(file.name); else files.push(file);
 }
 return {files,folders};
}

function armDropTarget() {
 const pane=$('#list');
 const mark=on => pane.classList.toggle('dropTarget',on);
 pane.addEventListener('dragover',ev => {
  if (!state.session?.canWrite) return;
  ev.preventDefault(); ev.stopPropagation();
  if (ev.dataTransfer) ev.dataTransfer.dropEffect='copy';
  mark(true);
 });
 // dragleave fires when the pointer crosses into a CHILD as well, so the
 // highlight is only dropped when the pointer has really left the pane.
 pane.addEventListener('dragleave',ev => { if (!pane.contains(ev.relatedTarget)) mark(false); });
 pane.addEventListener('drop',ev => {
  ev.preventDefault(); ev.stopPropagation();
  mark(false);
  if (!state.session?.canWrite) { error(new Error('Read-only mode is on. Open Settings to turn it off before uploading.')); return; }
  const {files,folders}=dropItems(ev.dataTransfer);
  if (folders.length) error(new Error(FOLDER_REFUSAL));
  if (files.length) uploadFiles(files,{path:state.path,pathB64:state.pathB64});
 });
}

export function initUpload() {
 const picker=$('#upFile');
 $('#btnUpload').addEventListener('click',() => { picker.value=''; picker.click(); });
 picker.addEventListener('change',() => {
  uploadFiles(picker.files,{path:state.path,pathB64:state.pathB64});
  // Cleared so choosing the SAME file again still fires a change event.
  picker.value='';
 });
 armDropTarget();
 // A queue belongs to a session. When one ends, everything still waiting is
 // cancelled rather than left to be uploaded as whoever signs in next.
 subscribe(() => {
  if (state.session) return;
  // The batch is invalidated FIRST, so anything still in flight — an XHR about
  // to be aborted, a dialog about to resolve — is already disowned by the time
  // its continuation runs and cannot put an entry back (finding 2).
  batch++;
  for (const item of queue.splice(0)) item.job.cancelled=true;
  for (const job of [...localJobs]) {
   if (!job.local) continue;
   job.cancelled=true;
   job.xhr?.abort();
   job.wake?.();        // a file waiting for a slot stops waiting too
   dropLocalJob(job.id);
  }
  repaintJobs();
 });
}
