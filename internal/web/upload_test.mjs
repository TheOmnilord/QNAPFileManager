// Run with: node --test internal/web/upload_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {uploadQueueOrder,uploadURL,progressOf,mergeJobs,conflictDecision,uploadError,isFolderDrop,uploadGrade,uploadRetryDelay,uploadWaitPlan,cancelAction,waitForSlot,CONFLICTS,FOLDER_REFUSAL,UPLOAD_NOTICES,UPLOAD_RETRY_CAP,UPLOAD_RETRY_BUDGET} from './static/js/upload.js';
import {archiveName,archiveURL,downloadMode,archiveNeedsTicket,archiveTicketRequest,archiveTicketURL,truncateBytes,FORMATS,ARCHIVE_URL_LIMIT,NAME_MAX} from './static/js/viewer.js';
import {TRANSFER_NOTICES} from './static/js/transfer.js';
import {confirmQueue,oneDialog,confirmTicket,confirmTicketValid,flushConfirmQueue} from './static/js/actions.js';
import {state,sameSession,sessionTransition} from './static/js/state.js';
import {jobStillOwned} from './static/js/upload.js';

// A File as the picker hands it over: only the four fields the request needs.
const file = (name,size = 10,lastModified = 1_700_000_000_000) => ({name,size,lastModified,type:'text/plain'});

// --- queue -------------------------------------------------------------------

test('uploadQueueOrder keeps the selection order and materialises a FileList', () => {
 const picked = [file('b.txt'),file('a.txt'),file('c.txt')];
 // A FileList is array-LIKE, not an Array; the queue needs something it can shift.
 const fileList = {length:3,0:picked[0],1:picked[1],2:picked[2],[Symbol.iterator]:function*(){ for (let i=0;i<this.length;i++) yield this[i]; }};
 const queue = uploadQueueOrder(fileList);
 assert.ok(Array.isArray(queue));
 assert.deepEqual(queue.map(f => f.name),['b.txt','a.txt','c.txt']); // never sorted
 assert.equal(uploadQueueOrder(null).length,0);
 assert.equal(uploadQueueOrder([null,undefined,file('x')]).length,1);
});

test('progressOf refuses to guess a percentage it cannot know', () => {
 assert.equal(progressOf(512,1024),50);
 assert.equal(progressOf(0,1024),0);
 assert.equal(progressOf(1024,1024),100);
 assert.equal(progressOf(2048,1024),100);   // clamped, never 200%
 assert.equal(progressOf(10,0),null);       // an empty or unknown length
 assert.equal(progressOf(10,-1),null);
 assert.equal(progressOf(NaN,1024),0);
});

// --- the request URL ---------------------------------------------------------

const query = url => new URL(url,'http://x/').searchParams;

test('uploadURL sends the folder in the byte spelling when it has one', () => {
 const bytes = query(uploadURL({path:'/share/�',pathB64:'L3NoYXJlL_8'},file('a.txt'),'skip'));
 assert.equal(bytes.get('dirB64'),'L3NoYXJlL_8');
 assert.equal(bytes.get('dir'),null);      // never both: one authority per request
 const typed = query(uploadURL({path:'/share/Public'},file('a.txt'),'skip'));
 assert.equal(typed.get('dir'),'/share/Public');
 assert.equal(typed.get('pathB64'),null);
});

test('uploadURL declares name, size and mtime in whole seconds', () => {
 const params = query(uploadURL({path:'/share'},file('holiday photo.jpg',4096,1_700_000_123_456),'skip'));
 assert.equal(params.get('name'),'holiday photo.jpg');   // a space is a legal name, and survives
 assert.equal(params.get('size'),'4096');
 assert.equal(params.get('mtime'),'1700000123');         // ms → s, floored
 assert.equal(params.get('conflict'),'skip');
 assert.equal(params.get('confirm'),null);
});

test('uploadURL says nothing about a timestamp it does not have', () => {
 const params = query(uploadURL({path:'/share'},{name:'a',size:0,lastModified:0},'skip'));
 assert.equal(params.get('mtime'),null);   // not "0", which would claim 1970
 assert.equal(params.get('size'),'0');     // an empty file has a known length
});

test('uploadURL carries confirm as a QUERY parameter, because the body is the file', () => {
 const params = query(uploadURL({path:'/share'},file('a.txt'),'overwrite','tok-123'));
 assert.equal(params.get('conflict'),'overwrite');
 assert.equal(params.get('confirm'),'tok-123');
});

test('uploadURL degrades an unknown policy to the one that destroys nothing', () => {
 for (const bad of ['clobber','',null,undefined,'OVERWRITE']) {
  assert.equal(query(uploadURL({path:'/share'},file('a.txt'),bad)).get('conflict'),'skip');
 }
 for (const good of CONFLICTS) {
  assert.equal(query(uploadURL({path:'/share'},file('a.txt'),good)).get('conflict'),good);
 }
});

// --- the panel ---------------------------------------------------------------

const server = (id,jobState = 'running') => ({id,kind:'copy',state:jobState});
const local = (id,jobState = 'running') => ({id,kind:'upload',state:jobState,local:true});

test('mergeJobs puts this tab’s uploads first and never reshuffles either half', () => {
 const merged = mergeJobs([server('s1'),server('s2')],[local('upload-1'),local('upload-2')]);
 assert.deepEqual(merged.map(j => j.id),['upload-1','upload-2','s1','s2']);
});

test('mergeJobs lets the SERVER win an id collision', () => {
 // A local id is a local invention; a collision means something is wrong, and
 // the authoritative record is the one that survives.
 const merged = mergeJobs([server('upload-1','done')],[local('upload-1','running')]);
 assert.equal(merged.length,1);
 assert.equal(merged[0].state,'done');
 assert.equal(merged[0].local,undefined);
});

test('mergeJobs copes with either half being absent', () => {
 assert.deepEqual(mergeJobs(null,[local('upload-1')]).map(j => j.id),['upload-1']);
 assert.deepEqual(mergeJobs([server('s1')],null).map(j => j.id),['s1']);
 assert.deepEqual(mergeJobs(null,null),[]);
 assert.deepEqual(mergeJobs([null,server('s1')],[null]).map(j => j.id),['s1']);
});

// --- the conflict question ---------------------------------------------------

test('conflictDecision answers for one file, or for the whole rest of the batch', () => {
 assert.deepEqual(conflictDecision('overwrite',false,7),{policy:'overwrite',cancelled:false,remember:false,applies:1});
 assert.deepEqual(conflictDecision('overwrite',true,7),{policy:'overwrite',cancelled:false,remember:true,applies:8});
 assert.deepEqual(conflictDecision('rename',true,0),{policy:'rename',cancelled:false,remember:true,applies:1});
});

test('a dismissed conflict dialog cancels that file and sets no policy for the others', () => {
 // "Apply to all" ticked and then Escape must never become a standing policy:
 // the user answered nothing, least of all for files they were not asked about.
 assert.deepEqual(conflictDecision(null,true,7),{policy:null,cancelled:true,remember:false,applies:0});
 assert.deepEqual(conflictDecision('nonsense',true,7),{policy:null,cancelled:true,remember:false,applies:0});
});

test('conflictDecision never counts a negative remainder', () => {
 assert.equal(conflictDecision('skip',true,-3).applies,1);
 assert.equal(conflictDecision('skip',true,NaN).applies,1);
});

// --- reading one XHR response ------------------------------------------------

test('uploadError reads a 201 as the created entry', () => {
 const {data,error} = uploadError(201,JSON.stringify({path:'/share/a.txt',entry:{name:'a.txt'}}));
 assert.equal(error,undefined);
 assert.equal(data.path,'/share/a.txt');
});

test('uploadError carries the server code so the queue can act on it', () => {
 const exists = uploadError(409,JSON.stringify({error:{code:'exists',message:'A file with that name already exists here.'}}));
 assert.equal(exists.error.code,'exists');
 assert.equal(exists.error.status,409);
 const space = uploadError(507,JSON.stringify({error:{code:'no_space',message:'Not enough space.'}}));
 assert.equal(space.error.code,'no_space');
});

test('uploadError keeps the confirmation token a 409 confirm_required offers', () => {
 const {error} = uploadError(409,JSON.stringify({error:{code:'confirm_required',message:'This overwrites an existing file.'},confirm:{token:'tok-9',summary:{warnings:['Existing files may be overwritten by this operation.']}}}));
 assert.equal(error.code,'confirm_required');
 assert.equal(error.confirm.token,'tok-9');
 assert.deepEqual(error.confirm.summary.warnings,['Existing files may be overwritten by this operation.']);
});

test('uploadError survives a proxy answering HTML, and keeps the status', () => {
 // QTS proxies answer HTML for timeouts and overloads; the status is the only
 // fact left, and it must not be lost to a JSON parse failure.
 const {error} = uploadError(502,'<html>Bad gateway</html>');
 assert.equal(error.message,'Request failed (502)');
 assert.equal(error.status,502);
 assert.equal(error.code,undefined);
});

test('uploadError joins the message and the path the way api.js does', () => {
 const {error} = uploadError(403,JSON.stringify({error:{code:'protected',message:'Protected system path',path:'/etc'}}));
 assert.equal(error.message,'Protected system path — /etc');
});

// --- the confirmation ladder (round 2, finding 2) ----------------------------

test('UPLOAD_NOTICES is pinned to the route, verbatim', () => {
 // routes_upload.go emits exactly one notice sentence, shared with the transfer
 // route; TestUploadNoticesArePinnedToTheClient holds the Go side to it.
 assert.deepEqual(UPLOAD_NOTICES,['Existing files may be overwritten by this operation.']);
 // The same sentence the transfer route writes, so editing one and not the
 // other shows up here rather than as a missing confirmation on a NAS.
 assert.ok(TRANSFER_NOTICES.includes(UPLOAD_NOTICES[0]));
});

test('uploadGrade: the route’s own notice is loud, not dangerous', () => {
 assert.equal(uploadGrade(null),1);
 assert.equal(uploadGrade({}),1);
 assert.equal(uploadGrade({warnings:[]}),1);
 assert.equal(uploadGrade({warnings:[...UPLOAD_NOTICES]}),1);
});

test('uploadGrade: a GUARD reason demands the typed name', () => {
 // The bug this exists for: uploading into /etc/config — firmware
 // configuration — reached a plain one-click confirm. Contract §1.4 says
 // protected is L2 via the ladder.
 const guardReason = 'Writing here can change how the NAS boots.';
 assert.equal(uploadGrade({warnings:[guardReason]}),2);
 // Mixed: one route notice and one guard reason is still L2. The presence of a
 // recognised sentence must never dilute an unrecognised one.
 assert.equal(uploadGrade({warnings:[UPLOAD_NOTICES[0],guardReason]}),2);
 assert.equal(uploadGrade({warnings:[guardReason,UPLOAD_NOTICES[0]]}),2);
});

test('uploadGrade treats a near-miss of the pinned sentence as a guard reason', () => {
 // Fail SAFE: if the route's wording drifts, the client asks for MORE
 // confirmation, never less.
 assert.equal(uploadGrade({warnings:['Existing files may be overwritten by this operation']}),2); // no full stop
 assert.equal(uploadGrade({warnings:['existing files may be overwritten by this operation.']}),2); // case
});

// --- waiting for an admission slot (429 queue_full) --------------------------

test('uploadRetryDelay doubles from a second, then holds at thirty', () => {
 assert.deepEqual([0,1,2,3,4,5].map(uploadRetryDelay),[1000,2000,4000,8000,16000,30000]);
 // The cap holds for ever after: a long-lived crowd must not become a hang.
 assert.equal(uploadRetryDelay(6),UPLOAD_RETRY_CAP);
 assert.equal(uploadRetryDelay(50),UPLOAD_RETRY_CAP);
 assert.equal(uploadRetryDelay(1e6),UPLOAD_RETRY_CAP);   // 2**n is Infinity long before this
});

test('uploadRetryDelay treats nonsense as the first attempt', () => {
 assert.equal(uploadRetryDelay(0),1000);
 assert.equal(uploadRetryDelay(-3),1000);
 assert.equal(uploadRetryDelay(NaN),1000);
 assert.equal(uploadRetryDelay(undefined),1000);
});

test('uploadWaitPlan keeps waiting until the budget is spent, then gives up', () => {
 assert.deepEqual(uploadWaitPlan(0,0),{wait:1000,giveUp:false});
 assert.deepEqual(uploadWaitPlan(3,7000),{wait:8000,giveUp:false});
 assert.deepEqual(uploadWaitPlan(9,UPLOAD_RETRY_BUDGET-1),{wait:UPLOAD_RETRY_CAP,giveUp:false});
 // Two minutes of a full queue means something is wrong elsewhere, and a file
 // that waits for ever is a file nobody is told about.
 assert.deepEqual(uploadWaitPlan(9,UPLOAD_RETRY_BUDGET),{wait:0,giveUp:true});
 assert.deepEqual(uploadWaitPlan(9,UPLOAD_RETRY_BUDGET+5000),{wait:0,giveUp:true});
});

test('the back-off gives up after about two minutes, not sooner and not for ever', () => {
 // Walk the real schedule the way uploadOne does, and count.
 let waited = 0,attempt = 0,waits = [];
 for (;;) {
  const plan = uploadWaitPlan(attempt,waited);
  if (plan.giveUp) break;
  waits.push(plan.wait);
  waited += plan.wait;
  attempt++;
  assert.ok(waits.length < 20,'the schedule must terminate');
 }
 assert.deepEqual(waits,[1000,2000,4000,8000,16000,30000,30000,30000]);
 assert.equal(waited,121000);                      // ~2 minutes
 assert.ok(waited >= UPLOAD_RETRY_BUDGET,'it waits out the whole budget');
 assert.ok(waited <= UPLOAD_RETRY_BUDGET+UPLOAD_RETRY_CAP,'and not much past it');
});

test('cancelAction wakes a waiting job rather than aborting a finished request', () => {
 // The bug: after a 429 the completed XHR was still on the job, so Cancel took
 // the abort path — and abort() on a DONE request dispatches nothing, so the
 // thirty-second wait ran its full course with every later file behind it.
 assert.equal(cancelAction({state:'queued',wake:() => {},xhr:{}}),'wake');
 assert.equal(cancelAction({state:'queued',wake:() => {}}),'wake');
 assert.equal(cancelAction({state:'running',xhr:{}}),'abort');
 assert.equal(cancelAction({state:'queued'}),'finish');
});

test('cancelAction does nothing to a job that has already finished', () => {
 for (const state of ['done','failed','cancelled']) {
  assert.equal(cancelAction({state,wake:() => {},xhr:{}}),'none');
 }
 assert.equal(cancelAction(null),'none');
});

test('a cancel during the back-off wakes the wait at once, and no retry follows', async () => {
 // Composed exactly as cancelLocal and uploadOne do it, with an xhr whose
 // abort() would throw: proof that the transport path is not the one taken.
 const job = {state:'queued',xhr:{abort() { throw new Error('a finished request must not be aborted'); }}};
 const wait = waitForSlot(job,30000);
 assert.equal(cancelAction(job),'wake');
 job.cancelled = true;
 job.wake();
 const started = Date.now();
 await wait;
 assert.ok(Date.now()-started < 500,'the wait must not run its course');
 assert.equal(job.wake,null,'and must not stay wakeable');
 // What uploadOne does when the wait returns.
 let retries = 0;
 if (!job.cancelled) retries++;
 assert.equal(retries,0,'no retry may follow a cancelled wait');
});

test('an untouched back-off still runs its timer', async () => {
 const job = {state:'queued'};
 const started = Date.now();
 await waitForSlot(job,60);
 assert.ok(Date.now()-started >= 45,'the wait is a real wait when nobody cancels');
 assert.equal(job.wake,null);
});

test('a 429 is recognised by code or by status', () => {
 // The route answers 429 queue_full with Connection: close; a proxy in between
 // may deliver the status without the body.
 const byCode = uploadError(429,JSON.stringify({error:{code:'queue_full',message:'Too many uploads.'}}));
 assert.equal(byCode.error.code,'queue_full');
 assert.equal(byCode.error.status,429);
 const byStatus = uploadError(429,'<html>Too Many Requests</html>');
 assert.equal(byStatus.error.code,undefined);
 assert.equal(byStatus.error.status,429);
});

// --- dropped folders ---------------------------------------------------------

test('isFolderDrop believes the entry API before the heuristic', () => {
 assert.equal(isFolderDrop({isDirectory:true},{name:'Photos',size:0,type:''}),true);
 // A genuinely empty, extension-less FILE is the case the heuristic gets wrong,
 // which is exactly why the entry is asked first.
 assert.equal(isFolderDrop({isDirectory:false},{name:'LICENSE',size:0,type:''}),false);
});

test('isFolderDrop falls back to size 0 with no type where there is no entry API', () => {
 assert.equal(isFolderDrop(null,{name:'Photos',size:0,type:''}),true);
 assert.equal(isFolderDrop(null,{name:'a.txt',size:12,type:'text/plain'}),false);
 assert.equal(isFolderDrop(null,{name:'a.txt',size:0,type:'text/plain'}),false);
 assert.equal(isFolderDrop(null,null),false);
});

test('the folder refusal says what to do instead', () => {
 assert.match(FOLDER_REFUSAL,/Folders cannot be uploaded yet/);
});

// --- archive download (contract §2.4) ----------------------------------------

const dirEntry = (name,path) => ({name,path,type:'dir'});
const fileEntry = (name,path) => ({name,path,type:'file'});

test('downloadMode: one readable file leaves as itself, everything else as an archive', () => {
 assert.equal(downloadMode({count:0,entry:null}),'none');
 assert.equal(downloadMode({count:1,entry:fileEntry('a.txt','/share/a.txt')}),'file');
 assert.equal(downloadMode({count:1,entry:dirEntry('Photos','/share/Photos')}),'archive');
 assert.equal(downloadMode({count:3,entry:null}),'archive');
 // A single item that cannot be read as a plain file (a device, a broken link)
 // is not a plain download either; the archive route answers for it.
 assert.equal(downloadMode({count:1,entry:{name:'null',path:'/dev/null',type:'device'}}),'archive');
 assert.equal(downloadMode(),'none');
});

test('truncateBytes never splits a character', () => {
 assert.equal(truncateBytes('abc',10),'abc');       // already short enough
 assert.equal(truncateBytes('abcdef',3),'abc');
 // "€" is three bytes: a budget of 4 keeps one and drops the half of the next.
 assert.equal(truncateBytes('€€',4),'€');
 assert.equal(truncateBytes('€€',3),'€');
 assert.equal(truncateBytes('€€',2),'');            // no whole character fits
 // An astral character is four bytes and one code point; it survives whole or
 // not at all — never as half a surrogate pair.
 assert.equal(truncateBytes('🐟🐟',7),'🐟');
 assert.equal(truncateBytes('🐟🐟',8),'🐟🐟');
 assert.equal(truncateBytes(null,5),'');
 assert.ok(!truncateBytes('€€',4).includes('�'),'a cut must never produce a replacement character');
});

test('a generated archive name fits inside the 255-byte budget', () => {
 // A file may legitimately be named up to 255 bytes; appending ".tar.gz" made
 // 262 and the route refused the download outright.
 const long = 'a'.repeat(255);
 assert.equal(bytes(archiveName([dirEntry(long,`/share/${long}`)],'zip')),NAME_MAX);
 assert.equal(bytes(archiveName([dirEntry(long,`/share/${long}`)],'tgz')),NAME_MAX);
 assert.ok(archiveName([dirEntry(long,'/share/x')],'tgz').endsWith('.tar.gz'));
});

test('the truncation lands on a character boundary, not in the middle of one', () => {
 // 128 three-byte characters = 384 bytes; the budget for a .tar.gz base is 248,
 // which is NOT a multiple of three, so the naive cut would split a character.
 const wide = '€'.repeat(128);
 const name = archiveName([dirEntry(wide,'/share/x')],'tgz');
 assert.ok(bytes(name) <= NAME_MAX,`${bytes(name)} bytes`);
 assert.ok(!name.includes('�'),'no half character survived the cut');
 assert.ok(name.endsWith('.tar.gz'));
 assert.equal(name,'€'.repeat(82)+'.tar.gz');   // 82*3 = 246 ≤ 248
});

test('a name with nothing left after trimming falls back to the neutral one', () => {
 assert.equal(archiveName([dirEntry('','/share/x')],'zip'),'archive.zip');
 assert.equal(archiveName([dirEntry(null,'/share/x')],'zip'),'archive.zip');
});

test('archiveName lends one item its own name, and only one', () => {
 assert.equal(archiveName([dirEntry('Photos','/share/Photos')],'zip'),'Photos.zip');
 assert.equal(archiveName([dirEntry('Photos','/share/Photos')],'tgz'),'Photos.tar.gz');
 assert.equal(archiveName([dirEntry('A','/a'),dirEntry('B','/b')],'zip'),'archive.zip');
 assert.equal(archiveName([],'zip'),'archive.zip');
 assert.equal(archiveName([dirEntry('','/x')],'zip'),'archive.zip');
 assert.equal(archiveName([dirEntry('P','/p')],'nonsense'),'P.zip'); // an unknown format is a zip
 assert.deepEqual(Object.keys(FORMATS),['zip','tgz']);
});

test('archiveURL repeats every root as its own parameter, in its own spelling', () => {
 const url = archiveURL([{name:'A',path:'/share/A',type:'dir'},{name:'B',path:'/share/�',pathB64:'L3NoYXJlL_8',type:'dir'}],'zip');
 const params = query(url);
 assert.deepEqual(params.getAll('path'),['/share/A']);
 assert.deepEqual(params.getAll('pathB64'),['L3NoYXJlL_8']);
 assert.equal(params.get('format'),'zip');
 assert.equal(params.get('name'),'archive.zip');
 assert.equal(params.get('crossMounts'),null);
 assert.ok(url.startsWith('api/fs/archive?'));
});

test('archiveURL passes crossing only when it is asked to', () => {
 const on = query(archiveURL([dirEntry('A','/share/A')],'tgz',{crossMounts:true}));
 assert.equal(on.get('crossMounts'),'1');
 assert.equal(on.get('format'),'tgz');
 assert.equal(on.get('name'),'A.tar.gz');
 assert.equal(query(archiveURL([dirEntry('A','/share/A')],'tgz',{crossMounts:false})).get('crossMounts'),null);
});

test('archiveURL lets the caller name the download', () => {
 assert.equal(query(archiveURL([dirEntry('A','/share/A')],'zip',{name:'selection.zip'})).get('name'),'selection.zip');
});

// --- one question at a time (round 6, finding 1) -----------------------------

const bytes = text => new TextEncoder().encode(text).length;

// settled() flushes the microtask queue, which is where the chain schedules the
// next question.
const settled = () => new Promise(resolve => setTimeout(resolve,0));

test('confirmQueue lets the second question open only after the first is settled', async () => {
 // The bug: emptying the Trash was waiting for the word "empty" to be typed
 // when a background upload re-dressed the SAME dialog and attached a second
 // handler. One click resolved both — the Trash was emptied without the phrase.
 await asSession(me,async () => {
  const order = [];
  let settleFirst;
  const first = confirmQueue(() => { order.push('first opened'); return new Promise(r => { settleFirst = r; }); });
  const second = confirmQueue(() => { order.push('second opened'); return Promise.resolve('B'); });
  try {
   await settled();
   // The first question is open and the second, though already raised by the
   // background upload, has not touched the dialog.
   assert.deepEqual(order,['first opened'],'the second question must not have opened yet');
   settleFirst('A');
   assert.deepEqual(await Promise.all([first,second]),['A','B']);
   assert.deepEqual(order,['first opened','second opened']);
  } finally {
   // Never leave the shared chain pending: the queue is module state, and a
   // half-finished test would hang every test after it.
   settleFirst?.('A');
  }
 });
});

test('confirmQueue keeps its order when a question is REFUSED, not just accepted', async () => {
 await asSession(me,async () => {
  const order = [];
  const a = confirmQueue(async () => { order.push('a'); return false; });
  const b = confirmQueue(async () => { order.push('b'); return true; });
  assert.deepEqual(await Promise.all([a,b]),[false,true]);
  assert.deepEqual(order,['a','b']);
 });
});

test('a thrown question does not poison the queue for everyone after it', async () => {
 await asSession(me,async () => {
  const boom = confirmQueue(() => Promise.reject(new Error('boom')));
  await assert.rejects(boom,/boom/);
  assert.equal(await confirmQueue(() => Promise.resolve('still works')),'still works');
 });
});

// --- a question belongs to the session that raised it (round 8) --------------

const me = {user:'sveinung',uid:1000,csrf:'a'};
const someoneElse = {user:'someone-else',uid:1234,csrf:'b'};
// The queue reads the live session, so these tests set it and put it back.
const asSession = async (session,body) => { state.session = session; try { return await body(); } finally { state.session = null; } };

test('confirmTicketValid keeps a refresh and refuses a switch or a sign-out', () => {
 const ticket = confirmTicket(me,3);
 assert.equal(confirmTicketValid(ticket,{...me,csrf:'rotated'}),true);   // a refresh
 assert.equal(confirmTicketValid(ticket,{...me,readOnly:true}),true);
 assert.equal(confirmTicketValid(ticket,someoneElse),false);             // a switch
 assert.equal(confirmTicketValid(ticket,{user:'sveinung',uid:1001}),false);
 assert.equal(confirmTicketValid(ticket,null),false);                    // a sign-out
 assert.equal(confirmTicketValid(null,me),false);
});

test('a question queued under one session is refused after a switch, and never opens', async () => {
 // The bug: signInNotice() closed the dialog on screen, its close event
 // advanced the queue, and the departed user's next question opened for
 // whoever had just signed in — who could approve it, whereupon runMutation
 // reposted the old operation with the NEW user's CSRF token.
 await asSession(me,async () => {
  let opened = 0,releaseFirst;
  const first = confirmQueue(() => new Promise(r => { releaseFirst = r; }));   // holds the queue
  const second = confirmQueue(() => { opened++; return Promise.resolve(true); });
  await settled();
  state.session = someoneElse;     // the switch
  flushConfirmQueue();             // what the session subscriber does, before any dialog closes
  releaseFirst(true);              // the active dialog closes and the queue advances
  assert.equal(await second,false,'a disowned question must answer "no"');
  assert.equal(opened,0,'and must never reach the screen');
  await first;
 });
});

test('a REFRESH leaves a queued question exactly where it was', async () => {
 await asSession(me,async () => {
  let opened = 0,releaseFirst;
  const first = confirmQueue(() => new Promise(r => { releaseFirst = r; }));
  const second = confirmQueue(() => { opened++; return Promise.resolve('asked'); });
  await settled();
  state.session = {...me,csrf:'rotated'};    // a read-only toggle from another tab
  releaseFirst(true);
  assert.equal(await second,'asked','the same user is still the right person to ask');
  assert.equal(opened,1);
  await first;
 });
});

test('an approval given as the user changes underneath is refused', async () => {
 // This is the check that actually stops the repost: the question was on screen
 // and answered, but not by the person it was asked of.
 const answer = await asSession(me,() => confirmQueue(async () => {
  state.session = someoneElse;   // they sign in while the dialog is up
  return true;                   // and click OK
 }));
 assert.equal(answer,false,'an approval must not outlive the user who was asked');
});

test('a disowned question answers in the caller’s own vocabulary', async () => {
 // An upload's conflict question answers with a decision, not a bare false, so
 // the queue that receives it does not have to special-case a refusal.
 const refusal = conflictDecision(null,false,3);
 const answer = await asSession(me,async () => {
  const p = confirmQueue(() => Promise.resolve({policy:'overwrite'}),refusal);
  state.session = someoneElse;
  flushConfirmQueue();
  return p;
 });
 assert.deepEqual(answer,refusal);
 assert.equal(answer.cancelled,true);
});

// --- one dialog lifecycle at a time (round 7, finding 1) ---------------------

// A fake dialog whose `close` event arrives a task LATER, exactly as a real
// <dialog>'s does: close() clears .open synchronously and queues the event.
function fakeDialog() {
 const listeners = new Set();
 return {
  open:false,
  addEventListener(type,fn) { if (type === 'close') listeners.add(fn); },
  removeEventListener(type,fn) { listeners.delete(fn); },
  show() { this.open = true; },
  close() { if (!this.open) return; this.open = false; setTimeout(() => { for (const fn of [...listeners]) fn(); },0); },
 };
}

test('a stray close from the PREVIOUS dialog cannot cancel the next one', async () => {
 // The bug: the first question resolved from its OK handler, which released the
 // queue; the second set itself up and opened; and only then did the first
 // dialog's close event arrive — delivered to whatever listeners existed by
 // then, which were the second question's. It answered "cancelled" and removed
 // its own handlers, leaving an open, unresponsive modal.
 await asSession(me,async () => {
  const dlg = fakeDialog(),order = [];
  const ask = (label,answer) => confirmQueue(() => oneDialog(dlg,finish => {
   order.push(`${label} opened`);
   dlg.show();
   setTimeout(() => finish(answer),0);        // the user answers
   return () => order.push(`${label} torn down`);
  },'cancelled'));
  const [first,second] = await Promise.all([ask('first','A'),ask('second','B')]);
  assert.equal(first,'A');
  assert.equal(second,'B','the second question must answer for itself, not be cancelled');
  assert.deepEqual(order,['first opened','first torn down','second opened','second torn down']);
  assert.equal(dlg.open,false,'no dialog may be left open');
 });
});

test('oneDialog resolves only once the element has really shut', async () => {
 await asSession(me,async () => {
  const dlg = fakeDialog();
  let closedBefore = null;
  const answer = await oneDialog(dlg,finish => { dlg.show(); setTimeout(() => finish('yes'),0); return () => { closedBefore = dlg.open; }; },'no');
  assert.equal(answer,'yes');
  assert.equal(closedBefore,false,'teardown runs from the close event, with the dialog already shut');
 });
});

test('an answer accepted under one session is refused when the close fires under another', async () => {
 // The window is the close event's own asynchrony: OK records the answer and
 // closes, the switch lands, and the close then handed the departed user's
 // answer to a caller that had not yet captured a session guard. Alice's folder
 // name was created in Bob's directory, with Bob's CSRF token.
 state.session = me;
 const dlg = fakeDialog();
 const answer = await oneDialog(dlg,finish => {
  dlg.show();
  setTimeout(() => { finish('alice-folder'); state.session = someoneElse; },0);
  return () => {};
 },null);
 state.session = null;
 assert.equal(answer,null,'an answer must not be handed to whoever signed in next');
});

test('a refresh during the close still delivers the answer', async () => {
 // The counterpart: a rotated token or a toggled setting is the same user, and
 // discarding their answer would be its own bug.
 state.session = me;
 const dlg = fakeDialog();
 const answer = await oneDialog(dlg,finish => {
  dlg.show();
  setTimeout(() => { finish('alice-folder'); state.session = {...me,csrf:'rotated'}; },0);
  return () => {};
 },null);
 state.session = null;
 assert.equal(answer,'alice-folder');
});

test('a sign-out during the close discards the answer too', async () => {
 state.session = me;
 const dlg = fakeDialog();
 const answer = await oneDialog(dlg,finish => {
  dlg.show();
  setTimeout(() => { finish({mode:'permanent'}); state.session = null; },0);
  return () => {};
 },null);
 assert.equal(answer,null);
});

test('oneDialog refuses an element somebody else is already using', async () => {
 const dlg = fakeDialog();
 dlg.show();
 let ran = false;
 assert.equal(await oneDialog(dlg,() => { ran = true; },'refused'),'refused');
 assert.equal(ran,false,'an occupied dialog is never re-dressed');
});

// --- an upload torn down mid-flight (round 7, finding 2) ---------------------

test('a completion that lands after teardown never re-inserts the entry', () => {
 // A session ending aborts the XHR and removes the entry; the abort's rejection
 // arrives afterwards and used to "finish" the job, putting the previous user's
 // file name back on screen for the next person in the same tab.
 const job = {id:'upload-1',batch:1,local:true};
 assert.equal(jobStillOwned(job,1,true),true);     // the ordinary case
 assert.equal(jobStillOwned(job,2,false),false);   // torn down: newer batch AND removed
 assert.equal(jobStillOwned(job,2,true),false);    // a stale batch, even if an id collides
 assert.equal(jobStillOwned(job,1,false),false);   // still this batch, but cleared from the panel
 assert.equal(jobStillOwned(null,1,true),false);
 assert.equal(jobStillOwned({id:'x'},1,true),false); // no batch stamp is not ownership
});

// --- a refresh is not a sign-in (round 7, finding 3) -------------------------

test('sessionTransition tells a refresh from a sign-out and from a switch', () => {
 const me = {user:'sveinung',uid:1000};
 assert.equal(sessionTransition(me,{...me,readOnly:true}),'refresh');  // toggled in another tab
 assert.equal(sessionTransition(me,{...me,csrf:'rotated'}),'refresh');
 assert.equal(sessionTransition(null,me),'refresh');                   // the first connect
 assert.equal(sessionTransition(me,null),'signout');
 assert.equal(sessionTransition(null,null),'signout');
 assert.equal(sessionTransition(me,{user:'admin',uid:0}),'switch');
 assert.equal(sessionTransition(me,{user:'sveinung',uid:1001}),'switch'); // same name, different uid
});

test('only a switch may tear anything down', () => {
 // The rule showSession applies, stated once: everything that is not a change
 // of user leaves in-flight work alone.
 const me = {user:'sveinung',uid:1000};
 for (const after of [{...me,readOnly:true},{...me,canWrite:false},me]) {
  assert.notEqual(sessionTransition(me,after),'switch');
 }
});

// --- a session that was refreshed, not ended (round 6, finding 2) ------------

const session = (user,uid) => ({user,uid,csrf:'t',canWrite:true});

test('sameSession sees a REFRESHED session as the same session', () => {
 // settings.js re-reads the session after a read-only toggle and app.js re-reads
 // it every minute. Both replace the object and bump the generation; neither
 // means the user went away, and an upload guarded by the generation was
 // abandoned mid-stream with its panel entry stuck on "running".
 const before = session('sveinung',1000);
 assert.equal(sameSession(before,{...before,readOnly:true}),true);   // a settings change
 assert.equal(sameSession(before,{...before,csrf:'rotated'}),true);  // a rotated token
 assert.equal(sameSession(before,before),true);
});

test('sameSession still stops an upload when the user really goes away', () => {
 const before = session('sveinung',1000);
 assert.equal(sameSession(before,null),false);                       // signed out
 assert.equal(sameSession(before,session('admin',0)),false);         // a different user
 assert.equal(sameSession(before,session('sveinung',1001)),false);   // same name, different uid
 assert.equal(sameSession(null,before),false);
 assert.equal(sameSession(null,null),false);
});

// --- the selection ticket (round 4) ------------------------------------------

// A selection of ordinary-looking files with long-ish names — nothing exotic
// for a NAS, and enough of them that the GET request line no longer fits.
const many = count => Array.from({length:count},(_,i) =>
 fileEntry(`Concert recording ${String(i).padStart(4,'0')} — remastered.flac`,
           `/share/Music/2026/Concert recording ${String(i).padStart(4,'0')} — remastered.flac`));

test('a small selection goes straight out as a GET', () => {
 assert.equal(archiveNeedsTicket(archiveURL([dirEntry('Photos','/share/Photos')],'zip')),false);
 assert.equal(archiveNeedsTicket(archiveURL(many(20),'zip')),false);
});

test('a large selection is too big for a URL and must buy a ticket', () => {
 // The bug: the server caps request headers and answers 431 before the handler
 // runs, so the download simply never happened.
 const url = archiveURL(many(300),'zip');
 assert.ok(url.length > ARCHIVE_URL_LIMIT,'the fixture must actually be oversized');
 assert.equal(archiveNeedsTicket(url),true);
});

test('archiveNeedsTicket counts BYTES, not JavaScript characters', () => {
 assert.equal(ARCHIVE_URL_LIMIT,8192);
 assert.equal(archiveNeedsTicket('a'.repeat(ARCHIVE_URL_LIMIT)),false);      // exactly at the limit
 assert.equal(archiveNeedsTicket('a'.repeat(ARCHIVE_URL_LIMIT+1)),true);
 // One character, three bytes: a string under the limit whose bytes are over it.
 assert.equal(archiveNeedsTicket('☃'.repeat(ARCHIVE_URL_LIMIT/2)),true);
 assert.equal(archiveNeedsTicket(''),false);
 assert.equal(archiveNeedsTicket(null),false);
});

test('archiveTicketRequest carries the selection the URL would have carried', () => {
 const entries = [dirEntry('A','/share/A'),{name:'B',path:'/share/�',pathB64:'L3NoYXJlL_8',type:'dir'}];
 assert.deepEqual(archiveTicketRequest(entries,'tgz',{crossMounts:true}),{
  paths:[{path:'/share/A'},{pathB64:'L3NoYXJlL_8'}],   // each in its own spelling, as pathArgs gives it
  format:'tgz',name:'archive.tar.gz',crossMounts:true,
 });
});

test('archiveTicketRequest says nothing about crossing unless asked, and names one item', () => {
 const body = archiveTicketRequest([dirEntry('Photos','/share/Photos')],'zip');
 assert.deepEqual(body,{paths:[{path:'/share/Photos'}],format:'zip',name:'Photos.zip'});
 assert.equal('crossMounts' in body,false);
 assert.equal(archiveTicketRequest([],'nonsense').format,'zip');  // an unknown format is a zip
 assert.equal(archiveTicketRequest([dirEntry('A','/a')],'zip',{name:'selection.zip'}).name,'selection.zip');
});

test('archiveTicketURL spends the token and nothing else', () => {
 const url = archiveTicketURL('tok-123');
 assert.equal(query(url).get('sel'),'tok-123');
 // The ticket IS the selection: no paths, no format, no name ride along.
 for (const key of ['path','pathB64','format','name','crossMounts']) assert.equal(query(url).get(key),null);
 assert.ok(url.startsWith('api/fs/archive?'));
 assert.ok(!archiveNeedsTicket(url),'the ticket URL must itself be small');
});
