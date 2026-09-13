import {api} from './api.js';
import {$,el,error,announce,pathArgs} from './dom.js';
import {state,sessionGuard} from './state.js';
import {loadList} from './list.js';
import {loadTree} from './tree.js';
import {propsTarget} from './viewer.js';
import {mergeJobs} from './upload.js';

// The jobs panel (ui-ux §3.4): a right-side drawer listing every operation this
// session can see, polled while anything is live and silent when nothing is.
//
// Everything that formats a number is a pure function at the top of this file,
// so the wording of "1,204 / 3,900 files · 8.2 / 14.1 GiB · 112 MiB/s · ~52 s
// left" is unit-tested rather than eyeballed.

const UNITS = ['B','KiB','MiB','GiB','TiB','PiB'];

// formatBytes renders a byte count in binary units, with one decimal below 100
// so "8.2 GiB" and "112 MiB" both read naturally.
export function formatBytes(bytes) {
 const n = Number(bytes);
 if (!Number.isFinite(n) || n < 0) return '—';
 let value = n, unit = 0;
 while (value >= 1024 && unit < UNITS.length-1) { value /= 1024; unit++; }
 if (unit === 0) return `${Math.round(value)} B`;
 return `${value >= 100 ? Math.round(value) : Number(value.toFixed(1))} ${UNITS[unit]}`;
}

export function formatRate(bytesPerSecond) {
 const n = Number(bytesPerSecond);
 if (!Number.isFinite(n) || n <= 0) return '';
 return `${formatBytes(n)}/s`;
}

// formatETA turns the server's seconds-remaining into words. -1 means unknown,
// and unknown is said by saying nothing rather than by guessing.
export function formatETA(seconds) {
 const s = Number(seconds);
 if (!Number.isFinite(s) || s < 0) return '';
 if (s < 60) return `~${Math.round(s)} s left`;
 if (s < 3600) { const m = Math.floor(s/60), rest = Math.round(s%60); return rest ? `~${m} m ${rest} s left` : `~${m} m left`; }
 const h = Math.floor(s/3600), m = Math.round((s%3600)/60);
 return m ? `~${h} h ${m} m left` : `~${h} h left`;
}

// jobPercent is the fraction complete, or null when the job is indeterminate —
// a capped scan reports a total of -1 (design §3) and the bar then has no
// meaningful denominator, so it is shown as indeterminate instead of guessed.
export function jobPercent(job) {
 if (!job) return null;
 // A LOCAL entry knows its own percentage — an upload is measured by the
 // transport, not by a count the server reports — so it is believed rather than
 // re-derived. A server job never carries this field.
 if (Number.isFinite(job.percent)) return Math.max(0,Math.min(100,job.percent));
 if (job.bytesTotal > 0) return Math.max(0,Math.min(100,Math.round(job.bytes/job.bytesTotal*100)));
 if (job.filesTotal > 0) return Math.max(0,Math.min(100,Math.round(job.files/job.filesTotal*100)));
 return null;
}

export const jobLive = job => job && (job.state === 'queued' || job.state === 'running');
export const shouldPoll = list => Array.isArray(list) && list.some(jobLive);

// jobBarState is the value for the row's <progress>, or null for the animated
// indeterminate bar. A terminal job is NEVER indeterminate — a finished job used
// to keep animating when it had no denominator: done is full (100), a stopped
// job holds the fraction it reached (or 0). Only a RUNNING job with no
// meaningful total stays indeterminate.
export function jobBarState(job) {
 if (!jobLive(job)) return job && job.state === 'done' ? 100 : (jobPercent(job) ?? 0);
 return jobPercent(job);
}

// jobDetailLine is the panel's second line. Counts with no total drop the
// denominator rather than printing "of -1"; a rate or an ETA that is not known
// is simply absent.
export function jobDetailLine(job) {
 if (!job) return '';
 const parts = [];
 // Show the denominator only for a MEANINGFUL total (> 0). A metadata job
 // (trash, restore, size) never sets a files total, so it stays 0, and a capped
 // scan reports -1; both are non-positive and must read "N files", not the
 // "1 / 0 files" a >= 0 test produced.
 parts.push(job.filesTotal > 0
  ? `${job.files.toLocaleString()} / ${job.filesTotal.toLocaleString()} files`
  : `${job.files.toLocaleString()} files`);
 if (job.bytes > 0 || job.bytesTotal > 0) {
  parts.push(job.bytesTotal > 0
   ? `${formatBytes(job.bytes)} / ${formatBytes(job.bytesTotal)}`
   : formatBytes(job.bytes));
 }
 // A rate and an ETA are only meaningful while the job runs; a finished job's
 // last estimate is stale (a "done" job used to still show e.g. "21 GiB/s"). An
 // ETA of 0 means "about to finish", not worth saying.
 if (jobLive(job)) {
  const rate = formatRate(job.rate); if (rate) parts.push(rate);
  if (job.eta > 0) parts.push(formatETA(job.eta));
 }
 return parts.join(' · ');
}

// jobTitle is "kind → target": the Title the server composed, falling back to
// the kind when a job has none.
export function jobTitle(job) { return job?.title || job?.kind || 'Operation'; }

// createPoller is the polling loop, with its timer injected so a test can drive
// it without waiting. load() returns whether polling should continue; the next
// tick is only scheduled once the previous one has answered, so a slow response
// cannot stack requests.
export function createPoller({load,interval=500,timers=globalThis}) {
 let handle = null, stopped = true;
 const tick = async () => {
  handle = null;
  let again = false;
  try { again = await load(); } catch { again = false; }
  if (!stopped && again) schedule();
 };
 const schedule = () => { if (handle === null) handle = timers.setTimeout(tick,interval); };
 return {
  start() { stopped = false; schedule(); },
  stop() { stopped = true; if (handle !== null) { timers.clearTimeout(handle); handle = null; } },
  get running() { return handle !== null; },
  tick,
 };
}

// --- panel ------------------------------------------------------------------

const dismissed = new Set();   // ids the user cleared from the panel locally
// trackedStates is id -> the last state this session saw, so only TRANSITIONS
// are announced and acted on. It is seeded at submit (seedJob) as well as by
// polling: a short job can reach its terminal state before the first
// GET /api/jobs answers, and without a previous state such a job used to be
// skipped entirely — no completion handling, no list or tree refresh, and the
// poller stopping with the work invisible (round 2, finding W8).
export const trackedStates = new Map();
let poller = null;
let refreshAfterJob = false;
// primed marks that one full listing has been seen. The very first listing of a
// session is a BASELINE: it can hold finished jobs retained from minutes ago (or
// another session's), and announcing a backlog of completions nobody just asked
// for would be noise. Everything after it is a real transition.
let primed = false;

// REFRESH_KINDS are the kinds whose completion changes what the list and the
// tree show, so finishing one reloads both. `upload` is here for the same
// reason, though no SERVER job ever carries that kind: an upload is a local
// entry (below) and upload.js reloads the listing once when its queue drains —
// the rule is the same rule, applied on the side that owns the work. `search`
// is deliberately absent: it changes nothing (contract §3.4).
const REFRESH_KINDS = new Set(['delete','trash-restore','trash-empty','copy','move','upload']);

// localJobs are operations this TAB is performing that the server has no job
// for — uploads, which are a stream of bytes into one route rather than a job
// on the manager. They are shaped exactly like a server job so every formatter
// here treats them alike; the two differences are that they never poll (nothing
// to poll) and that `cancel` is their own, because there is no id to POST to.
export const localJobs = [];
// serverJobs is the last listing seen, kept so a local entry's progress can
// repaint the panel without inventing a server state or waiting for the poll.
let serverJobs = [];

// Insertion and update are DELIBERATELY separate operations. A single
// create-or-update setter looks tidier and hid a real bug: a session ending
// aborted an upload and removed its entry, the abort's rejection arrived a
// moment later, and the "finish" that followed re-inserted the entry that had
// just been torn down — leaving the previous user's file name on screen for the
// next one (round 7, finding 2). Only makeJob may insert; every continuation
// updates, and an update to an entry that is gone is a no-op.
export function addLocalJob(job) {
 if (!job?.id || hasLocalJob(job.id)) return false;
 localJobs.push(job);
 return true;
}
export function updateLocalJob(job) {
 const at = localJobs.findIndex(j => j.id === job?.id);
 if (at < 0) return false;      // removed: nothing to update, and nothing to resurrect
 localJobs[at] = job;
 return true;
}
export const hasLocalJob = id => localJobs.some(j => j.id === id);
export function dropLocalJob(id) {
 const at = localJobs.findIndex(j => j.id === id);
 if (at >= 0) localJobs.splice(at,1);
}

function panelOpen(open) {
 $('#jobsPanel').hidden = !open;
 $('#btnJobs').setAttribute('aria-expanded',String(open));
}

// showJobsPanel opens the drawer for work that was just started somewhere else
// (an upload queue), without the poll trackJob would trigger for a server job.
export function showJobsPanel() { panelOpen(true); }

function jobRow(job) {
 const row = el('div',{id:`job-${job.id}`,class:`job job-${job.state}`,role:'group','aria-label':jobTitle(job)});
 const head = el('div',{class:'jobHead'});
 head.append(el('span',{class:'jobTitle'},jobTitle(job)));
 const percent = jobPercent(job);
 head.append(el('span',{class:'jobPct'},jobLive(job) ? (percent === null ? '…' : `${percent}%`) : job.state));
 if (jobLive(job)) {
  const cancel = el('button',{id:`jobCancel-${job.id}`,class:'jobCancel'},'Cancel');
  // A local entry cancels itself (it aborts its own transport); a server job is
  // cancelled by asking the manager.
  cancel.addEventListener('click',() => job.local ? job.cancel?.() : cancelJob(job.id));
  head.append(cancel);
 }
 row.append(head);
 const bar = el('progress',{id:`jobBar-${job.id}`,max:100});
 // A <progress> with no value attribute renders INDETERMINATE (an animated
 // sweep). jobBarState gives every terminal job a value so a finished job never
 // keeps animating; only a running job with no denominator stays indeterminate.
 const barValue = jobBarState(job);
 if (barValue !== null) bar.value = barValue;
 row.append(bar);
 row.append(el('p',{class:'jobLine'},jobDetailLine(job)));
 if (job.current && jobLive(job)) row.append(el('p',{class:'jobCurrent'},`now: ${job.current}`));
 if (job.note) row.append(el('p',{class:'jobNote'},job.note));
 if (job.error && job.state === 'failed') row.append(el('p',{class:'jobNote'},job.error));
 if (job.warningCount) {
  const box = el('details',{id:`jobErrors-${job.id}`,class:'errbox'});
  box.append(el('summary',{},`Show warnings (${job.warningCount.toLocaleString()})`));
  const list = el('ul',{});
  for (const warning of job.warnings || []) list.append(el('li',{},warning));
  if (job.warningCount > (job.warnings || []).length) list.append(el('li',{},`… and ${(job.warningCount-(job.warnings||[]).length).toLocaleString()} more`));
  box.append(list); row.append(box);
 }
 return row;
}

// jobTransitions computes what changed since the last poll and updates the
// state map in place. Pure enough to unit-test: given a listing and the states
// previously seen, it says which jobs started, which finished, and whether the
// file list needs reloading.
//
// A job seen for the first time ALREADY terminal counts as having finished
// (finding W8) — that is what a job which outran the first poll looks like —
// unless this is the priming listing, which only records a baseline.
export function jobTransitions(list,previous,{prime=false} = {}) {
 const events = [];
 let refresh = false;
 for (const job of list) {
  const before = previous.get(job.id);
  if (before === job.state) continue;
  const first = before === undefined;
  previous.set(job.id,job.state);
  if (first && prime) continue;
  if (jobLive(job)) { if (first) events.push({job,kind:'started'}); continue; }
  events.push({job,kind:'finished'});
  if (REFRESH_KINDS.has(job.kind)) refresh = true;
 }
 for (const id of [...previous.keys()]) if (!list.some(j => j.id === id)) previous.delete(id);
 return {events,refresh};
}

// seedJob records the state a job was in when its 202 came back, so a job that
// finishes before the first poll still reads as a transition (finding W8).
export function seedJob(job) { if (job?.id && job.state) trackedStates.set(job.id,job.state); }

// announceTransitions says only what §3.4 permits: a job started, a job
// finished. Percentages are never announced — a screen reader repeating "37%,
// 38%, 39%" twice a second is unusable.
function announceTransitions(list) {
 const {events,refresh} = jobTransitions(list,trackedStates,{prime:!primed});
 primed = true;
 for (const {job,kind} of events) {
  announce(kind === 'started'
   ? `${jobTitle(job)} started.`
   : `${jobTitle(job)} ${job.state === 'done' ? 'finished' : job.state}.`);
 }
 if (refresh) refreshAfterJob = true;
}

// renderJobs paints the panel from the server's listing MERGED with this tab's
// local entries. Passing null repaints from the last listing seen, which is how
// an upload's progress reaches the panel between polls.
export function renderJobs(list) {
 if (Array.isArray(list)) serverJobs = list;
 const visible = mergeJobs(serverJobs,localJobs).filter(j => !dismissed.has(j.id));
 $('#jobsList').replaceChildren(...visible.map(jobRow));
 $('#jobsEmpty').hidden = visible.length > 0;
 const live = visible.filter(jobLive).length;
 $('#btnJobs').textContent = live ? `Operations (${live})` : 'Operations';
}

// repaintJobs is renderJobs with no new listing: local progress only.
export function repaintJobs() { renderJobs(null); }

// refreshJobs polls once and reports whether anything is still live. A failure
// is shown but does not stop the loop from being restarted by the next submit.
export async function refreshJobs() {
 if (!state.session) return false;
 const valid = sessionGuard();
 const data = await api('api/jobs');
 if (!valid()) return false;
 const list = data.jobs || [];
 announceTransitions(list);
 renderJobs(list);
 if (refreshAfterJob) { refreshAfterJob = false; loadList(); loadTree(); }
 return shouldPoll(list) && !document.hidden;
}

// pollJobs starts (or restarts) the 500 ms loop. It is called after every
// submit and whenever the tab becomes visible again; the loop stops itself when
// nothing is queued or running.
export function pollJobs() {
 if (!poller) return;
 poller.stop();
 refreshJobs().then(again => { if (again) poller.start(); }).catch(err => error(err));
}

export async function cancelJob(id) {
 const valid = sessionGuard();
 try {
  await api(`api/jobs/${id}/cancel`,{},{method:'POST'});
  if (valid()) pollJobs();
 } catch(err) { if (valid()) error(err); }
}

// trackJob shows the panel for a job that was just submitted and starts polling.
// It records the submitted state first (finding W8), so however fast the job
// finishes its completion is still seen as a transition.
export function trackJob(job) {
 if (!job) return;
 seedJob(job);
 dismissed.delete(job.id);
 panelOpen(true);
 // pollJobs refreshes immediately and then every 500 ms while anything is
 // live, so the new job appears from the same listing as everything else
 // rather than being painted alone and then replaced.
 pollJobs();
}

// awaitJob resolves with the finished job, polling until it leaves the live
// states. Used by "Calculate size", which has a result to show.
//
// It polls the SINGLE-job endpoint deliberately. Waiting on the panel's listing
// instead would look like a saving and is not one: GET /api/jobs omits the bulk
// parts of a result (a search's hits), so a caller that has a result to show
// must ask about its own job by id. search.js makes that request itself rather
// than inheriting this one — see searchJobView there.
export async function awaitJob(id,{tries=1200,delay=500} = {}) {
 for (let i = 0; i < tries; i++) {
  const valid = sessionGuard();
  const data = await api(`api/jobs/${id}`);
  if (!valid()) return null;
  if (!jobLive(data.job)) return data.job;
  await new Promise(resolve => setTimeout(resolve,delay));
 }
 return null;
}

// calculateSize runs a size job for whatever the Properties dialog is showing
// and fills the result in when it finishes (ui-ux §3.6). The job is visible in
// the panel like any other, so a measurement of a huge tree can be cancelled.
export async function calculateSize() {
 const entry = propsTarget();
 if (!entry) return;
 const valid = sessionGuard();
 $('#btnCalcSize').disabled = true; $('#propsSize').textContent = 'Calculating…';
 try {
  const res = await api('api/jobs/size',{},{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({paths:[pathArgs(entry)],crossMounts:state.session?.family==='quts_hero'})});
  if (!valid()) return;
  trackJob(res.job);
  const job = await awaitJob(res.job.id);
  if (!valid() || propsTarget() !== entry) return;
  if (!job) { $('#propsSize').textContent = 'Still measuring — see Operations.'; return; }
  if (job.state !== 'done') { $('#propsSize').textContent = job.note || job.error || `Measurement ${job.state}.`; return; }
  const result = job.result || {};
  $('#propsSize').textContent = `${formatBytes(result.bytes||0)} in ${(result.files||0).toLocaleString()} file(s) and ${(result.dirs||0).toLocaleString()} folder(s)`;
 } catch(err) { if (valid()) { $('#propsSize').textContent = err.message; error(err); } }
 finally { if (valid()) $('#btnCalcSize').disabled = false; }
}

export function initJobs() {
 poller = createPoller({load:refreshJobs});
 $('#btnCalcSize').addEventListener('click',calculateSize);
 $('#btnJobs').addEventListener('click',() => { const open = $('#jobsPanel').hidden; panelOpen(open); if (open) pollJobs(); });
 $('#btnJobsClose').addEventListener('click',() => panelOpen(false));
 $('#btnJobsClear').addEventListener('click',async () => {
  // The manager reaps finished jobs on its own schedule, so "clear" is local:
  // it hides what this session has already seen rather than pretending to
  // delete a record somebody else may still need.
  // A finished LOCAL entry has no server record to retain, so it is simply
  // forgotten rather than added to the dismissed set.
  for (const job of [...localJobs]) if (!jobLive(job)) dropLocalJob(job.id);
  try { const data = await api('api/jobs'); for (const job of data.jobs || []) if (!jobLive(job)) dismissed.add(job.id); }
  catch(err) { repaintJobs(); error(err); return; }
  pollJobs();
 });
 document.addEventListener('visibilitychange',() => { if (document.hidden) poller.stop(); else pollJobs(); });
}
