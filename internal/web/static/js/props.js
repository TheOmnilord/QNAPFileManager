import {api} from './api.js';
import {$,el,error,announce,openDialog,pathArgs} from './dom.js';
import {state,sessionGuard} from './state.js';
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
export function sizeRequest(entries,{crossMounts = false} = {}) {
 const list = (Array.isArray(entries) ? entries : [entries]).filter(Boolean);
 const body = {paths:list.map(pathArgs)};
 if (crossMounts) body.crossMounts = true;
 return body;
}

// sizeReport turns a finished (or unfinished) size job into what the dialog
// says. Pure, so the four outcomes are unit-tested rather than watched for.
export function sizeReport(job) {
 if (!job) return {state:'pending',text:'Still measuring — see Operations.',result:null};
 if (job.state !== 'done') return {state:job.state,text:job.note || job.error || `Measurement ${job.state}.`,result:job.result || null};
 const r = job.result || {};
 return {
  state:'done',
  result:r,
  text:`${formatBytes(r.bytes || 0)} in ${(r.files || 0).toLocaleString()} file(s) and ${(r.dirs || 0).toLocaleString()} folder(s)`,
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
// sub-datasets are two different answers (decision 9).
export function sizeJobKey(entries,{crossMounts = false} = {}) {
 return JSON.stringify(sizeRequest(entries,{crossMounts}));
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

// resetSizeJobs drops every shared measurement. Tests use it; nothing else
// needs to, because an entry ages out on its own.
export function resetSizeJobs() { sizeJobs.clear(); }

// pruneSizeJobs collects measurements nobody holds and nobody may reuse. A
// session that walks a thousand folders would otherwise keep a thousand stale
// answers alive for the sake of a ten-second window.
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
 // abandon gives up on a measurement that never reached a terminal state.
 //
 // Whatever this side decided, the walk is still going on the server — so the
 // ID is the thing that must not be lost. Stop, the close event and Recount all
 // cancel by id, and an entry whose id stopped being reachable the moment
 // polling gave up left a du over a multi-terabyte share walking with nothing
 // able to stop it (round 1, finding 14). The entry is marked failed as well,
 // so the next dialog measures again rather than attaching to a walk nobody is
 // watching; `cancelled` makes this idempotent, because the poll giving up and
 // the dialog closing a moment later must not send two cancels for one job.
 function abandon(entry) {
  if (!entry || entry.cancelled) return undefined;
  entry.cancelled = true;
  entry.failed = true;
  if (sizeJobs.get(entry.key) === entry) sizeJobs.delete(entry.key);
  // The 202 may still be in flight; the submitting closure cancels it then.
  return entry.id ? cancel(entry.id) : undefined;
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
  // finished one has nothing to stop, and neither has one already cancelled
  // because its poll gave up.
  get jobId() { return held && !held.finishedAt && !held.cancelled ? held.id : null; },
  stop() {
   const had = held;
   run++; held = null;
   return release(had);
  },
  async start(entries,{crossMounts = false} = {}) {
   runner.stop();
   const ticket = run,valid = sessionGuard();
   const key = sizeJobKey(entries,{crossMounts});
   report({state:'running',text:'Measuring…',result:null});
   pruneSizeJobs();
   let entry = sizeJobs.get(key);
   if (!sizeJobUsable(entry)) {
    if (entry && sizeJobs.get(key) === entry) sizeJobs.delete(key);
    entry = null;
   }
   if (!entry) {
    entry = {key,id:null,holders:0,job:null,finishedAt:0,abandoned:false,failed:false,cancelled:false};
    entry.promise = (async () => {
     const res = await api('api/jobs/size',{},{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(sizeRequest(entries,{crossMounts}))});
     entry.id = res.job?.id ?? null;
     // Abandoned while the 202 was in flight: the job exists on the server and
     // nobody is waiting for it, so it is cancelled rather than left to walk.
     if (entry.abandoned) { if (entry.id) cancel(entry.id); return null; }
     // quiet: a measurement the user did not ask for as an operation must not
     // throw the Operations drawer over the dialog they are reading.
     track(res.job,{quiet:true});
     // A poll that answers null has NOT seen a terminal state: awaitJob ran out
     // of tries, or the session changed under it. Storing that as the answer set
     // finishedAt and put the entry out of cancelling reach, so the walk carried
     // on with nobody able to stop it; a thrown fetch error lost it the same way
     // (round 1, finding 14). Either way the job is cancelled by the id the
     // entry still holds, and the failure is what this measurement reports.
     let job;
     try { job = await poll(entry.id); }
     catch(err) { abandon(entry); throw err; }
     if (!job) { abandon(entry); throw new Error('The measurement did not answer, and it was stopped. Press Recount to measure again.'); }
     entry.job = job; entry.finishedAt = Date.now();
     return job;
    })();
    entry.promise.catch(() => {
     // A measurement that could not even be submitted is not an answer to
     // attach to; the next dialog asks again.
     entry.failed = true;
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
    if (ticket === run && valid()) { held = null; entry.holders--; report({state:'failed',text:err.message,result:null}); }
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
   sizeRunner.start([entry],{crossMounts:state.session?.family === 'quts_hero'});
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
  if (entry) sizeRunner.start([entry],{crossMounts:state.session?.family === 'quts_hero'});
 });
 $('#btnStopSize').addEventListener('click',() => { sizeRunner.stop(); $('#propsSize').textContent = 'Measurement stopped.'; $('#btnStopSize').disabled = true; });
}
