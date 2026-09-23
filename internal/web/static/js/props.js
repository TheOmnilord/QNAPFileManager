import {api} from './api.js';
import {$,el,error,announce,openDialog,pathArgs} from './dom.js';
import {state,sessionGuard,ownerGuard} from './state.js';
import {isDirectory,isSymlink} from './badges.js';
import {trackJob,awaitJob,cancelJob,formatBytes} from './jobs.js';
import {aclBadge,octal,parseOctal,symbolic} from './perm.js';
import {capsSentence} from './why.js';

// The Properties dialog (#dlgProps, Alt+Enter — ui-ux §3.6, M3 contract §8).
//
// GET /api/fs/properties is a PLAIN OP, not a job: one canonical walk, one
// fstat, one fstatfs, one xattr probe (§8.1). The one thing it cannot answer is
// how big a directory is, because that is a walk — so the size reuses the
// EXISTING size job (§8.4): submitted when the dialog opens on a folder,
// cancelled when it closes or Stop is pressed, resubmitted by Recount. No new
// job kind, no new route, and no second implementation of du.

// --- the size job runner (shared with #dlgPerms's #pImpact) -------------------

// sizeRequest is the body POST /api/jobs/size takes. Crossing is the hero
// question: a share whose sub-folders are separate datasets measures as nothing
// at all unless the walk is allowed to cross (decision 9).
//
// readCross is the measurement's PURPOSE (decision 9, amended; Astra r1 on the
// QKVM fix). Properties is a read and asks for the read rule, which may step
// from the /share RAM disk into a volume; the Permissions impact estimate
// predicts a chmod, which never does, and so never asks. It is sent only with
// crossing on, because without crossing the two rules give the same answer —
// and then the two dialogs may still share one walk (sizeJobKey).
export function sizeRequest(entries,{crossMounts = false,readCross = false} = {}) {
 const list = (Array.isArray(entries) ? entries : [entries]).filter(Boolean);
 const body = {paths:list.map(pathArgs)};
 if (crossMounts) body.crossMounts = true;
 if (crossMounts && readCross) body.readCross = true;
 return body;
}

// sizeReport turns a finished (or unfinished) size job into what the dialog
// says. Pure, so the four outcomes are unit-tested rather than watched for.
export function sizeReport(job) {
 if (!job) return {state:'pending',text:'Still measuring — see Operations.',result:null};
 if (job.state !== 'done') return {state:job.state,text:job.note || job.error || `Measurement ${job.state}.`,result:job.result || null};
 const r = job.result || {};
 // Mount points the walk did not enter are part of what the number leaves out
 // (PLAN.md decision 9), and a volume's worth of missing bytes has to be said.
 // Network shares are named apart: they are never measured at all.
 const whole = v => Math.max(0,Math.floor(Number(v) || 0));
 const mounts = whole(r.mountsSkipped),network = whole(r.mountsNetwork);
 const left = (mounts ? ` · ${mounts.toLocaleString()} mounted folder${mounts === 1 ? '' : 's'} not counted` : '')
  + (network ? ` · ${network.toLocaleString()} network share${network === 1 ? '' : 's'} not counted` : '');
 return {
  state:'done',
  result:r,
  text:`${formatBytes(r.bytes || 0)} in ${(r.files || 0).toLocaleString()} file(s) and ${(r.dirs || 0).toLocaleString()} folder(s)${left}`,
 };
}

// --- one measurement per folder, shared ---------------------------------------
//
// A size job is submitted by a DIALOG, not by the user, and two dialogs ask the
// same question about the same folder: Properties measures it, and Permissions'
// impact line measures it again. Opening Properties, closing it and opening it
// again asked a third time. Each of those was a separate job, so the Operations
// panel filled with identical "Calculating size: _IMAGES" rows (owner, hardware
// 0.0.133).
//
// So the measurement is keyed by the request it would send, and a dialog either
// attaches to the one already running or reuses one that finished a moment ago.
// `holders` is why sharing is safe: the walk is cancelled when the LAST dialog
// holding it goes away, not when the first one closes.
export const SIZE_REUSE_MS = 10000;
const sizeJobs = new Map();

// sizeJobKey is the identity of a measurement: the exact body it would post.
// Crossing is part of it — a share measured with and without crossing into its
// sub-datasets are two different answers (decision 9), and so are a read-rule
// measurement and a strict one: a relaxed total must never be shown as the
// impact of a chmod that will not cross, nor the reverse.
export function sizeJobKey(entries,{crossMounts = false,readCross = false} = {}) {
 return JSON.stringify(sizeRequest(entries,{crossMounts,readCross}));
}

// sizeJobUsable says whether an existing measurement may be attached to. Pure
// over the entry and the clock, so "fresh enough" is a unit test.
//
// Still running → yes, attach: a second dialog waits for the same walk. Done
// and recent → yes, reuse the answer. Anything else — failed, cancelled,
// abandoned, or simply old — is not an answer this dialog may present as its
// own, and it measures again.
export function sizeJobUsable(entry,now = Date.now(),window = SIZE_REUSE_MS) {
 if (!entry || entry.abandoned || entry.failed) return false;
 if (!entry.finishedAt) return true;
 if (entry.job?.state !== 'done') return false;
 return now - entry.finishedAt <= window;
}

// `pendingCancels` is every measurement the UI has ASKED the service to stop and
// that the service has not acknowledged stopping.
//
// It is the whole of Astra r3 #3: Stop dropped its reference to the entry before
// the cancel was sent, and abandon drops the entry from the shared cache, so when
// the RETRY cancel failed too nothing on this side still named the walk — jobId
// went null and a second Stop sent nothing while the du carried on. Ownership of
// an unacknowledged cancel therefore survives Stop, the close event and Recount:
// jobId keeps naming it, and each of those user actions retries it exactly once —
// never a loop — until the service answers.
//
// The register is MODULE-level, not one runner's, because the walk is shared
// (Astra r4 #3). Properties and Permissions hold one measurement whose 202 is
// still in flight; the last dialog to close asks for a stop that has no id to
// name yet, and the cancel finally goes out from the closure that POSTED the job
// — the FIRST dialog's runner. With a set per runner that was the only one that
// then named the walk, so the dialog the user was still looking at reported no
// job at all and its Stop and Recount sent nothing. The claim is written on the
// shared entry as well (`cancelPending`), so an entry that has left `sizeJobs`
// still carries it, and only an acknowledgement clears it.
const pendingCancels = new Set();

// claimed is the shared question every runner asks: has this measurement been
// asked to stop without the service saying it has? True from the moment a stop
// is asked for — including while the 202 is still in flight and there is no id
// to cancel by — until an acknowledgement clears it.
const claimed = entry => !!entry && !!entry.cancelPending && !entry.cancelled;

// A claim is one SESSION's, though, and the register outlives the sign-in that
// filled it (Astra r5 #6). Alice asks for a stop, the service does not answer, so
// the claim stands; the page is then switched to the administrator Bob, who opens
// Permissions — and the retry went out from BOB's runner, with Bob's CSRF token
// and Bob's credentials, against Alice's walk. jobCancel permits exactly that,
// because an administrator may cancel another user's job, so nothing downstream
// would have refused it.
//
// So the OWNER the claim was made under is written on the shared entry alongside
// the claim itself, and the retry is keyed on it rather than on any cross-module
// wiring: a claim from a session that is no longer this user's is DROPPED — not
// retried, and not left in the register either.
//
// The owner is `state.ownerEpoch`, not `state.sessionGeneration`. The generation
// moves on every session INSTALL, same-user refreshes included — settings.js
// re-reads the session after a read-only toggle, app.js re-reads it every minute
// — so scoping the claim by it made a refresh arriving mid-measurement look like
// somebody else's page: jobId went null and Stop and the close event dropped
// ownership without sending the cancel, while the du walked on (Astra r6 #1).
// The epoch moves only on a sign-out or a change of user, which is the question
// actually being asked here: is this still the person who asked for the stop?
const thisOwner = epoch => epoch === state.ownerEpoch;

// dropClaim ends a claim without sending anything. Either the service answered,
// or there is nobody left on this side with standing to ask.
const dropClaim = entry => { if (entry) { entry.cancelPending = false; pendingCancels.delete(entry); } };

// dropForeignClaims forgets every claim a previous session made. Every runner
// action sweeps with it, so a sign-out or a user switch needs nothing wired to
// it; it is exported so the session-transition path may say so explicitly.
export function dropForeignClaims() {
 for (const entry of [...pendingCancels]) if (!thisOwner(entry.cancelEpoch)) dropClaim(entry);
}

// resetSizeJobs drops every shared measurement, and the pending cancels with
// them. Tests use it — one test's unacknowledged claim is not the next one's
// walk — and nothing else does, because an entry ages out on its own.
export function resetSizeJobs() { sizeJobs.clear(); pendingCancels.clear(); }

// pruneSizeJobs collects measurements nobody holds and nobody may reuse. A
// session that walks a thousand folders would otherwise keep a thousand stale
// answers alive for the sake of a ten-second window. An unacknowledged cancel is
// not lost by this: the claim lives in `pendingCancels`, which is not this map.
export const SIZE_JOB_CAP = 32;
export function pruneSizeJobs(now = Date.now()) {
 if (sizeJobs.size <= SIZE_JOB_CAP) return;
 for (const [key,entry] of sizeJobs) {
  if (entry.holders <= 0 && !sizeJobUsable(entry,now)) sizeJobs.delete(key);
 }
}

// createSizeRunner owns at most ONE size job on behalf of one dialog.
//
// Every DOM-touching collaborator is injected, so the wiring itself — submit on
// open, cancel on close, Recount replaces — is testable with nothing but a
// mocked fetch. That matters more here than usual: the failure this guards
// against is a du over a multi-terabyte share still walking after the dialog
// that asked for it is gone, and it is invisible from a screenshot.
//
// `run` is the generation counter. Stopping bumps it, so a start that is still
// awaiting its job reports nothing when it finally answers, and a second start
// cannot be overtaken by the first.
export function createSizeRunner({report = () => {},track = trackJob,cancel = cancelJob,poll = awaitJob} = {}) {
 let held = null,run = 0;
 // The cancels this runner is waiting to have acknowledged are not its own:
 // they are in `pendingCancels`, above, because the measurement is shared.
 //
 // `cancelled` is ACKNOWLEDGED, never merely requested, and the distinction is
 // the whole of Astra r2 #9. The entry used to be marked cancelled before the
 // cancel was sent — so when the poll had given up because the connection was
 // lost, the cancel went down the same dead wire, failed the same way, and the
 // id was already out of reach: Stop, the close event and Recount then had
 // nothing left to retry while the du walked on. `cancelling` is the one on the
 // wire, so a request is never sent twice; a request that came back
 // UNACKNOWLEDGED clears it and leaves the entry retryable.
 function ack(entry,ok) {
  entry.cancelling = null;
  if (ok) { entry.cancelled = true; dropClaim(entry); }
  return ok;
 }
 // sendCancel is the only place a cancel is sent, and it answers a promise for
 // whether the server acknowledged it. It never rejects: nothing that calls it
 // is in a position to handle a failure other than by keeping the id.
 function sendCancel(entry) {
  if (entry.cancelled) { dropClaim(entry); return undefined; }
  // The walk belongs to the session that submitted it. Once that session is gone
  // — signed out, or replaced on this page by another user — this side has no
  // standing to stop it and no business trying with somebody else's credentials,
  // so the claim ends here rather than being carried (Astra r5 #6).
  // A refresh of the same user's session is not that, and must not end it
  // (Astra r6 #1) — it is still her walk, and she is still here to stop it.
  if (!thisOwner(entry.ownerEpoch)) { dropClaim(entry); return undefined; }
  // Asking is what makes the UI responsible for the stopping, and it stays
  // responsible until the service answers (Astra r3 #3). The claim is the
  // MEASUREMENT's, not the asking runner's, so every dialog that shares the walk
  // can retry it — including the one that let go of it last (Astra r4 #3) — but
  // only while the session that made it is still the current one (Astra r5 #6).
  entry.cancelPending = true;
  entry.cancelEpoch = state.ownerEpoch;
  pendingCancels.add(entry);
  // No id yet: the 202 is still in flight, and the submitting closure sends the
  // cancel the moment the id lands. The claim above is what carries the walk's
  // name across that gap — it used to be dropped here, and with it the only
  // record that anybody had asked (Astra r4 #3).
  if (!entry.id) return undefined;
  if (entry.cancelling) return entry.cancelling;
  // cancel() is called synchronously — Stop and the close event are asserted to
  // have cancelled by the time they return.
  let pending;
  try { pending = Promise.resolve(cancel(entry.id)); }
  catch(err) { pending = Promise.reject(err); }
  entry.cancelling = pending.then(ok => ack(entry,ok !== false),() => ack(entry,false));
  return entry.cancelling;
 }
 // retryStopping resends the cancels nobody has acknowledged. One attempt per
 // user action — sendCancel returns the request already on the wire rather than
 // starting a second — so a connection that stays down costs one request per
 // Stop, close or Recount and never a busy loop. `skip` is the entry this action
 // has just cancelled on its own account.
 //
 // A claim whose 202 has not landed is KEPT rather than collected: there is
 // nothing to send for it yet, and forgetting it is precisely how the walk lost
 // its name (Astra r4 #3).
 function retryStopping(skip) {
  // Claims made in a session that has ended are dropped before anything is
  // resent: they are not this user's walks to stop, and retrying one would send
  // it with this user's credentials (Astra r5 #6).
  dropForeignClaims();
  const sent = [];
  for (const entry of [...pendingCancels]) {
   // Collected: the service acknowledged it, or the walk it named reached an end
   // of its own. A claim with no id yet has named nothing and is neither.
   if (!claimed(entry) || (entry.id && !needsStop(entry))) { pendingCancels.delete(entry); continue; }
   if (entry === skip) continue;
   const pending = sendCancel(entry);
   if (pending) sent.push(pending);
  }
  return sent;
 }
 // needsStop is the question the runner keeps asking: is there still a walk on
 // the server that this side could stop? A finished measurement has nothing to
 // stop, an acknowledged cancel has already stopped it, and a job whose 202 has
 // not landed yet has no id to name.
 const needsStop = entry => !!entry && !entry.finishedAt && !entry.cancelled && !!entry.id;
 // abandon gives up on a measurement that never reached a terminal state.
 //
 // Whatever this side decided, the walk is still going on the server — so the
 // ID is the thing that must not be lost. Stop, the close event and Recount all
 // cancel by id, and an entry whose id stopped being reachable the moment
 // polling gave up left a du over a multi-terabyte share walking with nothing
 // able to stop it (round 1, finding 14). The entry is marked failed as well,
 // so the next dialog measures again rather than attaching to a walk nobody is
 // watching.
 function abandon(entry) {
  if (!entry || entry.cancelled) return undefined;
  entry.failed = true;
  if (sizeJobs.get(entry.key) === entry) sizeJobs.delete(entry.key);
  // The 202 may still be in flight; the submitting closure cancels it then.
  return sendCancel(entry);
 }
 // release is this runner letting go of a shared measurement. The walk is
 // cancelled only when nobody is left holding it: a du over a multi-terabyte
 // share must not outlive the last dialog that asked — and must not be killed
 // out from under a dialog that is still waiting for it either.
 function release(entry) {
  if (!entry) return undefined;
  entry.holders--;
  if (entry.holders > 0) return undefined;
  // A FINISHED measurement is kept for the reuse window: closing Properties and
  // opening it again on the same folder a second later must not walk it twice.
  // sizeJobUsable ages it out, and pruneSizeJobs collects it.
  if (entry.finishedAt) return undefined;
  entry.abandoned = true;
  return abandon(entry);
 }
 const runner = {
  // jobId is the measurement this runner could still cancel, and only that: a
  // finished one has nothing to stop, and neither has one whose cancel the
  // server has ACKNOWLEDGED. One whose cancel never got there is still
  // cancellable, and saying so is the point (Astra r2 #9) — including after the
  // Stop, close or Recount that let go of it, because letting go of the hold is
  // not the same as having stopped the walk (Astra r3 #3).
  get jobId() {
   if (needsStop(held) && thisOwner(held.ownerEpoch)) return held.id;
   // A request still ON THE WIRE is being attended to, and this side has nothing
   // to do about that walk until it answers. One that came BACK unacknowledged
   // is the one still waiting for another attempt, and it keeps its name until
   // it gets one (Astra r3 #3) — whichever dialog sent it, because the claim is
   // the measurement's (Astra r4 #3). A claim from a session that has ended names
   // nothing here: this user is not the one who asked (Astra r5 #6). A session
   // merely REFRESHED is the same user, and her walk keeps its name (Astra r6 #1).
   for (const entry of pendingCancels) {
    if (claimed(entry) && thisOwner(entry.cancelEpoch) && !entry.cancelling && needsStop(entry)) return entry.id;
   }
   return null;
  },
  // stop() lets go of the measurement this runner holds and, in the same breath,
  // has one more go at every cancel still waiting to be acknowledged. The answer
  // is awaitable, so a test — and a caller that cares — can wait for the service
  // rather than for the request.
  stop() {
   const had = held;
   run++; held = null;
   const sent = [release(had),...retryStopping(had)].filter(Boolean);
   return sent.length ? Promise.all(sent).then(() => undefined) : undefined;
  },
  async start(entries,{crossMounts = false,readCross = false} = {}) {
   runner.stop();
   // The measurement is held to its OWNER, not to the session object it was
   // started under. A du over a multi-terabyte share runs for minutes, and the
   // session is replaced under it for reasons that are not the user going away:
   // a read-only toggle in another tab, the minute poll, a rotated token. With
   // sessionGuard here (and inside the poll) such a refresh made the wait answer
   // null, which cancelled the walk under a dialog that was still open — and
   // then suppressed the failure report it had just caused, so the dialog said
   // "Measuring…" for ever over a measurement nobody was making (Astra r7 #3).
   // A switch or a sign-out still ends it: that is what the epoch moves on.
   const ticket = run,valid = ownerGuard();
   const key = sizeJobKey(entries,{crossMounts,readCross});
   report({state:'running',text:'Measuring…',result:null});
   pruneSizeJobs();
   let entry = sizeJobs.get(key);
   if (!sizeJobUsable(entry)) {
    if (entry && sizeJobs.get(key) === entry) sizeJobs.delete(key);
    entry = null;
   }
   if (!entry) {
    // `ownerEpoch` is WHOSE walk this is: the only user who may ask for it to be
    // stopped (Astra r5 #6). It survives her session being refreshed under it,
    // which the generation did not (Astra r6 #1).
    entry = {key,id:null,holders:0,job:null,finishedAt:0,abandoned:false,failed:false,cancelled:false,cancelling:null,
     cancelPending:false,ownerEpoch:state.ownerEpoch,cancelEpoch:-1};
    entry.promise = (async () => {
     const res = await api('api/jobs/size',{},{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(sizeRequest(entries,{crossMounts,readCross}))});
     entry.id = res.job?.id ?? null;
     // Abandoned while the 202 was in flight: the job exists on the server and
     // nobody is waiting for it, so it is cancelled rather than left to walk.
     // This closure belongs to whichever runner submitted, which is not
     // necessarily the dialog that let go last — so the claim it makes here is
     // the shared entry's, and every holder can retry it (Astra r4 #3).
     if (entry.abandoned) { sendCancel(entry); return null; }
     // quiet: a measurement the user did not ask for as an operation must not
     // throw the Operations drawer over the dialog they are reading.
     track(res.job,{quiet:true});
     // A poll that answers null has NOT seen a terminal state: awaitJob ran out
     // of tries, or the OWNER changed under it — the same epoch the claims use,
     // so a refresh keeps polling and a switch gives up (Astra r7 #3), and the
     // wait and the cancel can no longer disagree about whose walk this is.
     // Storing that as the answer set
     // finishedAt and put the entry out of cancelling reach, so the walk carried
     // on with nobody able to stop it; a thrown fetch error lost it the same way
     // (round 1, finding 14). Either way the job is cancelled by the id the
     // entry still holds, and the failure is what this measurement reports.
     let job;
     try { job = await poll(entry.id,{guard:ownerGuard}); }
     catch(err) { abandon(entry); throw err; }
     if (!job) { abandon(entry); throw new Error('The measurement did not answer, and it was stopped. Press Recount to measure again.'); }
     entry.job = job; entry.finishedAt = Date.now();
     return job;
    })();
    entry.promise.catch(() => {
     // A measurement that could not even be submitted is not an answer to
     // attach to; the next dialog asks again. It is not a walk either: a stop
     // asked for while the POST was in flight named a job the server never
     // acknowledged having, so that claim ends here rather than being carried
     // for the rest of the session (Astra r4 #3). A poll that gave up is a
     // different failure — it has an id, and the claim on it stands.
     entry.failed = true;
     if (!entry.id) dropClaim(entry);
     if (sizeJobs.get(key) === entry) sizeJobs.delete(key);
    });
    sizeJobs.set(key,entry);
   }
   entry.holders++;
   held = entry;
   try {
    const job = await entry.promise;
    if (ticket !== run || !valid()) return null;
    report(sizeReport(job));
    return job;
   } catch(err) {
    if (ticket !== run || !valid()) return null;
    // Letting go of a failed measurement is what makes the next one a fresh
    // start — but a measurement whose cancel never REACHED the server is still
    // a walk this runner is the only one holding the id for, so it stays held
    // until the cancel is acknowledged and Stop, the close event and Recount
    // can each retry it (Astra r2 #9).
    const letGo = () => { if (held === entry && ticket === run) { held = null; entry.holders--; } };
    if (entry.cancelling) entry.cancelling.then(ok => { if (ok) letGo(); });
    else if (!needsStop(entry)) letGo();
    report({state:'failed',text:err.message,result:null});
    return null;
   }
  },
 };
 return runner;
}

// --- what the dialog shows ---------------------------------------------------

const text = value => (value === undefined || value === null || value === '' ? '—' : String(value));
const when = value => (value ? new Date(value).toLocaleString() : '—');

// KINDS names the entry types in the words a person uses.
const KINDS = {dir:'Folder',file:'File',symlink:'Symbolic link',fifo:'Named pipe (FIFO)',socket:'Socket',device:'Device'};

// ownerText shows the name AND the number, always. A name that does not resolve
// is not an error to hide — it is the answer, and the number is what the wire
// carries (§5.4).
export function ownerText(name,id,kind = 'user') {
 const tag = kind === 'group' ? 'gid' : 'uid';
 return name ? `${name} (${tag} ${id})` : `${tag} ${id}`;
}

// modeText is the two spellings of one mode side by side, the way ls shows it.
export function modeText(entry) {
 const bits = parseOctal(entry?.mode)?.value;
 if (bits === undefined) return text(entry?.modeStr || entry?.mode);
 return `${entry?.modeStr || symbolic(bits,entry?.type === 'dir')}  ${octal(bits)}`;
}

// flagsText is the §4.1 marker row, in words rather than colour.
export function flagsText(entry,fs) {
 const flags = [];
 if (entry?.class === 'protected') flags.push('🛡 Protected system path');
 if (entry?.class === 'warn') flags.push('⚠ Changes here need confirmation');
 if (entry?.mountPoint) flags.push('⏏ Mount point');
 if (entry?.isSymlink) flags.push('🔗 Symbolic link');
 if (entry?.hidden) flags.push('Hidden');
 if (fs?.readOnly) flags.push('🔒 Read-only filesystem');
 if (fs?.network) flags.push('Network filesystem');
 return flags.length ? flags.join(' · ') : '—';
}

// propsSections is the whole dialog as data: three groups of label/value rows,
// each with a `copy` flag for the two paths §3.6 wants a copy button on. Pure,
// so what the dialog claims about an entry is testable without a browser.
export function propsSections(data) {
 const entry = data?.entry || {},fs = data?.fs || {},acl = data?.acl || {},target = data?.target || null;
 // The guard's classification is a TOP-LEVEL field of the response, not a field
 // of the entry: it is the guard's own verdict on this path (normal / warn /
 // protected), which is a different question from the lexical hint a listing
 // row carries. Either spelling feeds the flag row.
 const classified = {...entry,class:data?.class || entry.class};
 const path = String(entry.path ?? '');
 const parent = path.slice(0,path.lastIndexOf('/')) || '/';
 const general = [
  ['Kind',KINDS[entry.type] || text(entry.type)],
  ['Location',text(parent)],
  ['Full path',text(path),{copy:path}],
  ['Size',isDirectory(entry) ? '' : `${Number(entry.size || 0).toLocaleString()} bytes`],
  ['Modified',when(entry.mtime)],
  ['Links',text(entry.nlink)],
 ];
 const id = data?.identity || data?.id || null;
 if (id) general.push(['Inode',text(id.i ?? id.ino)],['Device',text(id.d ?? id.dev)]);
 general.push(
  ['Filesystem',[fs.fsType,fs.mount,fs.readOnly ? 'read-only' : 'read-write',fs.network ? 'network' : ''].filter(Boolean).join(' · ') || '—'],
  ['Free space',fs.total ? `${formatBytes(fs.avail)} free of ${formatBytes(fs.total)}` : '—'],
  ['Flags',flagsText(classified,fs)],
 );
 const permissions = [
  ['Mode',modeText(entry)],
  ['Owner',ownerText(entry.user,entry.uid,'user')],
  ['Group',ownerText(entry.group,entry.gid,'group')],
 ];
 const badge = aclBadge(entry.acl ? entry : {acl:acl.state});
 if (badge) permissions.push(['ACL',badge.title]);
 else if (acl.backend) permissions.push(['ACL',acl.state === 'nfs4-trivial'
  ? 'An NFSv4 ACL that says exactly what the mode says; changing the mode is safe here.'
  : 'No extended ACL.']);
 if (acl.aclmode) permissions.push(['ZFS aclmode',`${acl.aclmode}${acl.dataset ? ` (dataset ${acl.dataset})` : ''}`]);
 const link = [];
 if (isSymlink(entry)) {
  link.push(['Target',text(entry.linkTarget)]);
  link.push(['Real path',text(entry.linkResolved || (target && target.path)),{copy:entry.linkResolved || target?.path || ''}]);
  if (target) link.push(['Target kind',KINDS[target.type] || text(target.type)],['Target mode',modeText(target)]);
  else if (!entry.linkResolved) link.push(['Target kind','Broken — the target does not resolve']);
 }
 return [
  {title:'General',rows:general},
  {title:'Permissions',rows:permissions},
  {title:'Link',rows:link,hidden:!link.length},
 ];
}

// --- the dialog --------------------------------------------------------------

// propsEntry is what the dialog is showing, so the size runner and the footer's
// Permissions… button both know what they are acting on without importing the
// list.
let propsEntry = null;
export const propsTarget = () => propsEntry;
let propsData = null;
export const propsPayload = () => propsData;

const sizeRunner = createSizeRunner({report:report => {
 $('#propsSize').textContent = report.text;
 $('#btnStopSize').disabled = report.state !== 'running';
}});

function paint(data) {
 const host = $('#propsContent');
 host.replaceChildren();
 for (const section of propsSections(data)) {
  if (section.hidden) continue;
  host.append(el('h3',{},section.title));
  const table = el('dl',{class:'propsRows'});
  for (const [label,value,opts] of section.rows) {
   table.append(el('dt',{},label));
   const dd = el('dd',{},String(value ?? ''));
   if (opts?.copy) {
    const button = el('button',{class:'copyPath',type:'button','aria-label':`Copy ${label}`},'Copy');
    button.addEventListener('click',async () => {
     try { await navigator.clipboard.writeText(opts.copy); announce('Path copied.'); }
     catch { error(new Error('Could not copy the path. Use the path field to copy it.')); }
    });
    dd.append(' ',button);
   }
   table.append(dd);
  }
  host.append(table);
 }
}

// properties opens the dialog for one entry. A folder starts its size job
// immediately (§8.4); a file already knows its size and starts nothing.
export async function properties(entry) {
 if (!entry) return;
 const valid = sessionGuard();
 propsEntry = entry; propsData = null;
 $('#propsTitle').textContent = `Properties — ${entry.name || entry.path}`;
 $('#propsContent').replaceChildren(el('p',{},'Loading…'));
 $('#propsSize').textContent = ''; $('#btnStopSize').disabled = true;
 openDialog('#dlgProps');
 try {
  const params = {...pathArgs(entry)};
  if (isSymlink(entry)) params.follow = '1';
  const data = await api('api/fs/properties',params);
  if (!valid() || propsEntry !== entry || !$('#dlgProps').open) return;
  propsData = data;
  paint(data);
  if (isDirectory(data.entry || entry)) {
   sizeRunner.start([entry],{crossMounts:state.session?.family === 'quts_hero',readCross:true});
  } else {
   $('#propsSize').textContent = `${Number((data.entry || entry).size || 0).toLocaleString()} bytes`;
  }
 } catch(err) {
  if (valid() && propsEntry === entry) { $('#propsContent').replaceChildren(el('p',{},err.message)); error(err); }
 }
}

// capsHint is the §5.2 sentence, shown as an explanation of a likely refusal
// and never as a lock: the grid stays editable and the kernel decides (INV-2).
//
// It IS the reason table's `capability` sentence (M4 contract §7.1), and there
// is one of it: why.js owns the wording so the toolbar, the context menu and
// this dialog cannot drift apart. The name stays because the permissions dialog
// and its tests have always called it that.
export function capsHint(session,entry,caps) { return capsSentence(session,entry,caps); }

export function initProps() {
 // The size job belongs to the dialog, so it ends when the dialog does —
 // however it ends. The close EVENT is the one place that is true: Escape, the
 // Close button, and signInNotice() closing every dialog on a session change
 // all arrive here, and none of them would be caught by a click handler.
 $('#dlgProps').addEventListener('close',() => { sizeRunner.stop(); propsEntry = null; propsData = null; });
 $('#btnCalcSize').addEventListener('click',() => {
  const entry = propsTarget();
  if (entry) sizeRunner.start([entry],{crossMounts:state.session?.family === 'quts_hero',readCross:true});
 });
 $('#btnStopSize').addEventListener('click',() => { sizeRunner.stop(); $('#propsSize').textContent = 'Measurement stopped.'; $('#btnStopSize').disabled = true; });
}
