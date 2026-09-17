// Run with: node --test internal/web/sizejobs_test.mjs
//
// Hardware report on 0.0.133: opening Properties popped the Operations drawer
// open over the dialog, and every open added another "Calculating size: …" row.
// Two things were wrong and both are fixed here:
//
//   the panel opens only for work the user started AS an operation, and
//   one folder is measured once, however many dialogs ask about it.
import assert from 'node:assert/strict';
import {test} from 'node:test';

class Node {
 constructor() { this.attrs = {}; this.children = []; this.textContent = ''; this.hidden = false; this.disabled = false; this.title = ''; this.classes = new Set();
  this.classList = {toggle: (n, on) => on ? this.classes.add(n) : this.classes.delete(n), add: n => this.classes.add(n), remove: n => this.classes.delete(n), contains: n => this.classes.has(n)};
 }
 setAttribute(k, v) { this.attrs[k] = String(v); }
 getAttribute(k) { return this.attrs[k] ?? null; }
 append(...kids) { this.children.push(...kids); }
 replaceChildren(...kids) { this.children = kids; }
 addEventListener() {}
 querySelector() { return null; }
 querySelectorAll() { return []; }
 focus() {}
}
const nodes = new Map();
const $ = sel => { if (!nodes.has(sel)) nodes.set(sel, new Node()); return nodes.get(sel); };
globalThis.document = {querySelector: $, createElement: () => new Node(), addEventListener() {}, activeElement: null, hidden: false, getElementById: () => null, styleSheets: []};
globalThis.window = {addEventListener() {}};
globalThis.matchMedia = () => ({matches: false});
globalThis.location = {hash: ''};

const {awaitJob, cancelJob, trackJob} = await import('./static/js/jobs.js');
const {update} = await import('./static/js/state.js');
const {
 SIZE_REUSE_MS, createSizeRunner, resetSizeJobs, sizeJobKey, sizeJobUsable,
} = await import('./static/js/props.js');

// --- the panel opens only for an operation the user started -------------------

test('a quiet submission registers the job and leaves the Operations panel shut', () => {
 $('#jobsPanel').hidden = true;
 $('#btnJobs').setAttribute('aria-expanded', 'false');
 trackJob({id: 'size-1', state: 'queued', kind: 'size'}, {quiet: true});
 assert.equal($('#jobsPanel').hidden, true, 'a dialog measuring a folder must not throw a drawer over the dialog');
 assert.equal($('#btnJobs').getAttribute('aria-expanded'), 'false');
});

test('a delete still opens it — that is a job the user started as an operation', () => {
 $('#jobsPanel').hidden = true;
 trackJob({id: 'del-1', state: 'queued', kind: 'delete'});
 assert.equal($('#jobsPanel').hidden, false);
 assert.equal($('#btnJobs').getAttribute('aria-expanded'), 'true');
 $('#jobsPanel').hidden = true;
});

test('a quiet job does not CLOSE a panel the user opened either', () => {
 $('#jobsPanel').hidden = false;
 trackJob({id: 'size-2', state: 'queued', kind: 'size'}, {quiet: true});
 assert.equal($('#jobsPanel').hidden, false, 'the size job is a real job and belongs in an open panel');
 $('#jobsPanel').hidden = true;
});

test('nothing at all happens for a job that is not there', () => {
 $('#jobsPanel').hidden = true;
 trackJob(null, {quiet: true});
 trackJob(undefined);
 assert.equal($('#jobsPanel').hidden, true);
});

// --- one folder, one measurement ---------------------------------------------

const dir = path => ({path, name: path.split('/').pop(), type: 'dir'});

function harness({poll} = {}) {
 const posts = [], cancelled = [], tracked = [], reports = [];
 const runner = createSizeRunner({
  report: r => reports.push(r),
  track: (job, options) => tracked.push({job, options}),
  cancel: async id => { cancelled.push(id); },
  poll: poll || (async id => ({id, state: 'done', result: {bytes: 2048, files: 3, dirs: 2}})),
 });
 return {runner, posts, cancelled, tracked, reports};
}
const mockFetch = (t, posts, id = () => 's1') => t.mock.method(globalThis, 'fetch', async (url, options) => {
 posts.push({url: String(url), body: options?.body ? JSON.parse(options.body) : null});
 return new Response(JSON.stringify({job: {id: id(), state: 'queued'}}), {status: 202});
});

test('the size runner submits QUIETLY', async t => {
 resetSizeJobs();
 const {runner, posts, tracked} = harness();
 mockFetch(t, posts);
 await runner.start([dir('/share/Public')]);
 assert.equal(tracked.length, 1);
 assert.deepEqual(tracked[0].options, {quiet: true}, 'the dialog’s own measurement never opens the drawer');
});

test('opening Properties twice on the same folder is ONE job', async t => {
 resetSizeJobs();
 const {runner, posts, tracked, cancelled} = harness();
 mockFetch(t, posts);
 await runner.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 runner.stop();                                   // the dialog's close event
 await runner.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 assert.equal(posts.length, 1, 'the second open reuses the measurement it just made');
 assert.equal(tracked.length, 1, 'and so adds no second row to Operations');
 assert.deepEqual(cancelled, [], 'a finished walk has nothing to cancel');
});

test('a second folder is a second job', async t => {
 resetSizeJobs();
 const ids = ['s1', 's2'];
 let at = 0;
 const {runner, posts, tracked} = harness({poll: async id => ({id, state: 'done', result: {bytes: 1, files: 1, dirs: 0}})});
 mockFetch(t, posts, () => ids[at++] || 's9');
 await runner.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 runner.stop();
 await runner.start([dir('/share/CACHEDEV1_DATA/Video')]);
 assert.equal(posts.length, 2);
 assert.equal(tracked.length, 2);
 assert.deepEqual(posts.map(p => p.body.paths[0].path), ['/share/CACHEDEV1_DATA/_IMAGES', '/share/CACHEDEV1_DATA/Video']);
});

test('the same folder measured with and without crossing is two measurements', async t => {
 resetSizeJobs();
 const {runner, posts} = harness();
 mockFetch(t, posts);
 await runner.start([dir('/share/Public')], {crossMounts: false});
 runner.stop();
 await runner.start([dir('/share/Public')], {crossMounts: true});
 assert.equal(posts.length, 2, 'crossing into sub-datasets is a different answer (decision 9)');
 assert.notEqual(sizeJobKey([dir('/share/Public')], {crossMounts: true}), sizeJobKey([dir('/share/Public')], {}));
});

test('two dialogs asking at once share one walk, and the first to close does not kill it', async t => {
 resetSizeJobs();
 let release;
 const pending = new Promise(resolve => { release = resolve; });
 const posts = [], cancelled = [], tracked = [];
 const make = reports => createSizeRunner({
  report: r => reports.push(r),
  track: (job, options) => tracked.push({job, options}),
  cancel: async id => { cancelled.push(id); },
  poll: () => pending,
 });
 mockFetch(t, posts);
 const propsReports = [], permsReports = [];
 const properties = make(propsReports), permissions = make(permsReports);
 const a = properties.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 const b = permissions.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 assert.equal(posts.length, 1, 'Properties and Permissions measure the same folder once');
 assert.equal(tracked.length, 1);
 properties.stop();
 assert.deepEqual(cancelled, [], 'the other dialog is still waiting for this walk');
 release({id: 's1', state: 'done', result: {bytes: 4096, files: 1, dirs: 1}});
 assert.equal(await a, null, 'the dialog that closed reports nothing');
 await b;
 assert.equal(permsReports.at(-1).state, 'done', 'the one still open gets the answer');
 permissions.stop();
});

test('when the LAST holder goes away the walk is cancelled', async t => {
 resetSizeJobs();
 let release;
 const pending = new Promise(resolve => { release = resolve; });
 const {runner, posts, cancelled} = harness({poll: () => pending});
 mockFetch(t, posts);
 const started = runner.start([dir('/share/Public')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 assert.equal(runner.jobId, 's1');
 runner.stop();
 assert.deepEqual(cancelled, ['s1'], 'a du over a multi-terabyte share must not outlive its dialog');
 assert.equal(runner.jobId, null);
 release({id: 's1', state: 'cancelled'});
 assert.equal(await started, null);
});

test('a cancelled or failed measurement is never reused as an answer', () => {
 const now = 1_000_000;
 assert.equal(sizeJobUsable({holders: 0, finishedAt: 0}, now), true, 'still running: attach');
 assert.equal(sizeJobUsable({finishedAt: now - 1000, job: {state: 'done'}}, now), true, 'recent: reuse');
 assert.equal(sizeJobUsable({finishedAt: now - SIZE_REUSE_MS - 1, job: {state: 'done'}}, now), false, 'stale: measure again');
 assert.equal(sizeJobUsable({finishedAt: now - 10, job: {state: 'cancelled'}}, now), false);
 assert.equal(sizeJobUsable({finishedAt: now - 10, job: {state: 'failed'}}, now), false);
 assert.equal(sizeJobUsable({finishedAt: 0, abandoned: true}, now), false);
 assert.equal(sizeJobUsable({finishedAt: 0, failed: true}, now), false);
 assert.equal(sizeJobUsable(null, now), false);
});

// --- a poll that gives up must not lose the job id ----------------------------
//
// awaitJob answers null when it runs out of tries and throws on a transient
// fetch failure. Neither is a terminal state, and both used to leave the walk
// running with nothing able to stop it: the entry recorded finishedAt (or was
// dropped by the failure handler) and Stop, close and Recount all cancel by id
// (round 1, finding 14).

test('a poll that GIVES UP cancels the walk instead of losing its id', async t => {
 resetSizeJobs();
 const {runner, posts, cancelled, reports} = harness({poll: async () => null});
 mockFetch(t, posts);
 assert.equal(await runner.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]), null);
 assert.deepEqual(cancelled, ['s1'], 'the du is stopped explicitly, by the id the entry still held');
 assert.equal(reports.at(-1).state, 'failed', 'and the dialog says so rather than reading "still measuring"');
 assert.equal(runner.jobId, null);
 runner.stop();                                   // the dialog's close event, a moment later
 assert.deepEqual(cancelled, ['s1'], 'one job, one cancel');
});

test('a poll that THROWS cancels the walk too, and reports the error', async t => {
 resetSizeJobs();
 const {runner, posts, cancelled, reports} = harness({poll: async () => { throw new Error('network went away'); }});
 mockFetch(t, posts);
 assert.equal(await runner.start([dir('/share/CACHEDEV1_DATA/Video')]), null);
 assert.deepEqual(cancelled, ['s1']);
 assert.equal(reports.at(-1).state, 'failed');
 assert.equal(reports.at(-1).text, 'network went away');
 runner.stop();
 assert.deepEqual(cancelled, ['s1'], 'stop() after an abandoned poll does not cancel a second time');
});

test('an abandoned measurement is not reused: the next start measures again', async t => {
 resetSizeJobs();
 let tries = 0;
 const {runner, posts, cancelled} = harness({
  poll: async id => { tries++; return tries === 1 ? null : {id, state: 'done', result: {bytes: 1, files: 1, dirs: 0}}; },
 });
 mockFetch(t, posts, () => (posts.length > 1 ? 's2' : 's1'));
 assert.equal(await runner.start([dir('/share/Public')]), null);
 assert.deepEqual(cancelled, ['s1']);
 const second = await runner.start([dir('/share/Public')]);
 assert.equal(posts.length, 2, 'a walk nobody watched is not an answer to attach to');
 assert.equal(second.state, 'done');
 runner.stop();
});

// --- a cancel that never reached the server is not a cancel (Astra r2 #9) -----
//
// The entry used to be marked cancelled BEFORE the cancel was sent. The poll
// gives up because the connection went away; the cancel goes down the same dead
// wire and fails the same way — and the id was already out of reach, so Stop,
// the close event and Recount had nothing left to retry while the du walked on.
// Requested is not acknowledged.

test('cancelJob answers whether the cancel was ACKNOWLEDGED, not whether it was sent', async t => {
 // The runner's retry is only as good as this answer. The SERVICE saying it has
 // the cancel, or that it has no such job, has stopped the walk or never had
 // one; anything else — including an answer somebody else composed — has stopped
 // nothing at all.
 t.mock.method(globalThis, 'fetch', async () => new Response(null, {status: 204}));
 assert.equal(await cancelJob('s1'), true, 'a 204 is the service answering');
 t.mock.restoreAll();
 t.mock.method(globalThis, 'fetch', async () =>
  new Response(JSON.stringify({error: {code: 'not_found', message: 'no such job'}}), {status: 404}));
 assert.equal(await cancelJob('s1'), true, 'a job the manager already reaped is not a walk to retry');
 t.mock.restoreAll();
 t.mock.method(globalThis, 'fetch', async () => { throw new TypeError('fetch failed'); });
 assert.equal(await cancelJob('s1'), false, 'this one never reached the service, so the du may still be walking');
});

test('a proxy answering for the service is not the service acknowledging (Astra r3 #2)', async t => {
 // The QTS reverse proxy replies 502 with an HTML page when the daemon is slow
 // or restarting. It is an error with a status and no `network` flag, and the
 // old rule — anything that is not a transport failure is an answer — marked a
 // job that is still walking cancelled for good.
 t.mock.method(globalThis, 'fetch', async () =>
  new Response('<html><body><h1>502 Bad Gateway</h1></body></html>', {status: 502, headers: {'Content-Type': 'text/html'}}));
 assert.equal(await cancelJob('s1'), false, 'the proxy spoke, not the manager: the du may still be walking');
 t.mock.restoreAll();
 t.mock.method(globalThis, 'fetch', async () =>
  new Response(JSON.stringify({error: {code: 'queue_full', message: 'Too many requests.'}}), {status: 429}));
 assert.equal(await cancelJob('s1'), false, 'a refusal to take the request is a reason to send it again');
 t.mock.restoreAll();
 t.mock.method(globalThis, 'fetch', async () =>
  new Response(JSON.stringify({error: {code: 'permission', message: 'Not yours.'}}), {status: 403}));
 assert.equal(await cancelJob('s1'), false, 'a 4xx that is not "no such job" says nothing about the walk');
});

test('a cancel that did NOT reach the server leaves the walk retryable, and the next Stop retries it', async t => {
 resetSizeJobs();
 const cancelled = [];
 const reports = [], posts = [];
 // The first cancel goes the way the poll went: nowhere.
 const runner = createSizeRunner({
  report: r => reports.push(r),
  track: () => {},
  cancel: async id => { cancelled.push(id); return cancelled.length > 1; },
  poll: async () => { throw new Error('network went away'); },
 });
 mockFetch(t, posts);
 assert.equal(await runner.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]), null);
 assert.deepEqual(cancelled, ['s1'], 'the cancel was attempted');
 assert.equal(reports.at(-1).state, 'failed');
 assert.equal(runner.jobId, 's1', 'unacknowledged: the id is still this runner’s to retry');
 await runner.stop();                             // Stop, the close event, or Recount
 assert.deepEqual(cancelled, ['s1', 's1'], 'and the retry is sent');
 assert.equal(runner.jobId, null, 'acknowledged this time: there is nothing left to stop');
 await runner.stop();
 assert.deepEqual(cancelled, ['s1', 's1'], 'one acknowledged cancel is the end of it — no third');
});

test('a cancel that THREW is retryable too, and an acknowledged one is never resent', async t => {
 resetSizeJobs();
 const cancelled = [];
 const posts = [];
 const runner = createSizeRunner({
  report: () => {},
  track: () => {},
  cancel: async id => { cancelled.push(id); if (cancelled.length === 1) throw new Error('fetch failed'); },
  poll: async () => null,                         // ran out of tries: not a terminal state
 });
 mockFetch(t, posts, () => (posts.length > 1 ? 's2' : 's1'));
 assert.equal(await runner.start([dir('/share/Public')]), null);
 assert.deepEqual(cancelled, ['s1']);
 assert.equal(runner.jobId, 's1');
 // Recount is a start(), and a start() stops what is held first: the retry goes
 // out before the second measurement is submitted.
 const second = await runner.start([dir('/share/Public')]);
 assert.equal(posts.length, 2, 'a walk nobody watched is not an answer to attach to');
 assert.equal(second, null);                      // this poll gave up too
 assert.deepEqual(cancelled, ['s1', 's1', 's2'],
  'Recount retried the cancel the poll failure could not send, and stopped its own walk too');
 await runner.stop();
 assert.deepEqual(cancelled, ['s1', 's1', 's2'], 'both are acknowledged now, and neither is resent');
});

// --- a cancel nobody acknowledged is still this runner's to retry (r3 #3) -----
//
// Stop dropped its reference to the entry before the cancel was sent, and
// abandon drops the entry from the shared cache — so when the RETRY failed too,
// nothing on this side still named the walk: jobId went null and the next Stop
// sent nothing at all. Letting go of the hold is not the same as having stopped
// the du.

test('Stop letting go is not the walk stopping: an unacknowledged cancel is retried by the next action', async t => {
 resetSizeJobs();
 const posts = [], cancelled = [];
 let acknowledge = false;                         // the wire is down to begin with
 const runner = createSizeRunner({
  report: () => {},
  track: () => {},
  cancel: async id => { cancelled.push(id); return acknowledge; },
  poll: () => new Promise(() => {}),              // the walk is still going
 });
 mockFetch(t, posts);
 runner.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 assert.equal(runner.jobId, 's1');
 await runner.stop();                             // the dialog's close event
 assert.deepEqual(cancelled, ['s1'], 'the cancel was attempted');
 assert.equal(runner.jobId, 's1', 'unacknowledged: the id is still this runner’s to name');
 await runner.stop();                             // Stop pressed again
 assert.deepEqual(cancelled, ['s1', 's1'], 'each user action retries once — and once is enough');
 assert.equal(runner.jobId, 's1');
 acknowledge = true;                              // the service is back
 await runner.stop();
 assert.deepEqual(cancelled, ['s1', 's1', 's1']);
 assert.equal(runner.jobId, null, 'acknowledged at last: there is nothing left to stop');
 await runner.stop();
 assert.deepEqual(cancelled, ['s1', 's1', 's1'], 'and nothing is sent after that');
});

test('Recount retries the cancel it could not send, and still measures again', async t => {
 resetSizeJobs();
 const posts = [], cancelled = [];
 let acknowledge = false;
 const runner = createSizeRunner({
  report: () => {},
  track: () => {},
  cancel: async id => { cancelled.push(id); return acknowledge; },
  // The first walk never answers; the one Recount submits does.
  poll: async id => (id === 's1' ? new Promise(() => {}) : {id, state: 'done', result: {bytes: 1, files: 1, dirs: 0}}),
 });
 mockFetch(t, posts, () => (posts.length > 1 ? 's2' : 's1'));
 runner.start([dir('/share/Public')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 assert.equal(runner.jobId, 's1');
 const second = await runner.start([dir('/share/Public')]);   // Recount
 assert.equal(posts.length, 2, 'a walk nobody watched is not an answer to attach to');
 assert.equal(second.state, 'done');
 assert.deepEqual(cancelled, ['s1'], 'Recount stopped the walk it replaced');
 assert.equal(runner.jobId, 's1', 'which the service never acknowledged, so it is still named');
 await runner.stop();                             // the dialog closes on the new answer
 assert.deepEqual(cancelled, ['s1', 's1'], 'and the old walk is retried, though this one finished');
 acknowledge = true;
 await runner.stop();
 assert.deepEqual(cancelled, ['s1', 's1', 's1']);
 assert.equal(runner.jobId, null);
});

// --- the claim belongs to the MEASUREMENT, not to the runner (Astra r4 #3) ----
//
// Properties and Permissions ask about the same folder, so one walk has two
// holders. Close the first, close the second while the 202 is STILL in flight,
// and the stop the last holder asked for has no id to name yet: the cancel goes
// out later, from the closure that posted the job — the first dialog's runner.
// A runner-local set of pending cancels was therefore the SUBMITTER's, and the
// dialog that let go last reported no job id at all: its Stop and its Recount
// sent nothing while the du walked on.

test('a cancel claimed while the 202 was in flight is retried by whichever dialog acts next (Astra r4 #3)', async t => {
 resetSizeJobs();
 const posts = [], cancelled = [];
 let acknowledge = false;                         // the wire is down to begin with
 let land;                                        // the 202 waits here until we let it land
 const submitted = new Promise(resolve => { land = resolve; });
 const make = () => createSizeRunner({
  report: () => {},
  track: () => {},
  cancel: async id => { cancelled.push(id); return acknowledge; },
  poll: () => new Promise(() => {}),              // the walk is still going
 });
 t.mock.method(globalThis, 'fetch', async (url, options) => {
  posts.push({url: String(url), body: options?.body ? JSON.parse(options.body) : null});
  await submitted;
  return new Response(JSON.stringify({job: {id: 's1', state: 'queued'}}), {status: 202});
 });
 const properties = make(), permissions = make();
 const a = properties.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 const b = permissions.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 assert.equal(posts.length, 1, 'Properties and Permissions measure the same folder once');
 await properties.stop();                         // Properties closes first
 assert.deepEqual(cancelled, [], 'the other dialog is still waiting for this walk');
 await permissions.stop();                        // and now the last holder lets go
 assert.deepEqual(cancelled, [], 'nothing to cancel yet: the 202 has not landed');
 land();
 await new Promise(resolve => setTimeout(resolve, 0));
 assert.deepEqual(cancelled, ['s1'], 'the submitting closure sends it the moment the id arrives');
 assert.equal(await a, null);
 assert.equal(await b, null);
 assert.equal(permissions.jobId, 's1', 'unacknowledged: the dialog that let go LAST still names the walk');
 assert.equal(properties.jobId, 's1', 'and so does the one whose closure sent the request');
 await permissions.stop();                        // Stop in the dialog that never sent the first cancel
 assert.deepEqual(cancelled, ['s1', 's1'], 'and it retries — one attempt per user action');
 acknowledge = true;                              // the service is back
 await permissions.stop();
 assert.deepEqual(cancelled, ['s1', 's1', 's1']);
 assert.equal(permissions.jobId, null, 'acknowledged at last: there is nothing left to stop');
 assert.equal(properties.jobId, null, 'and one acknowledgement clears the walk for BOTH dialogs');
 await properties.stop();
 await permissions.stop();
 assert.deepEqual(cancelled, ['s1', 's1', 's1'], 'neither dialog sends a fourth');
});

test('a claim made before the id exists does not outlive a submission the server refused (Astra r4 #3)', async t => {
 // The other end of the same gap: both dialogs let go while the POST is in
 // flight, and the POST comes back 403. There is no walk on the server, so the
 // claim ends there rather than being carried — and cancelled — for the rest of
 // the session by every Stop the user presses afterwards.
 resetSizeJobs();
 const cancelled = [];
 let refuse;
 const answered = new Promise(resolve => { refuse = resolve; });
 const make = () => createSizeRunner({
  report: () => {},
  track: () => {},
  cancel: async id => { cancelled.push(id); return false; },
  poll: () => new Promise(() => {}),
 });
 t.mock.method(globalThis, 'fetch', async () => {
  await answered;
  return new Response(JSON.stringify({error: {code: 'protected', message: 'no'}}), {status: 403});
 });
 const properties = make(), permissions = make();
 const a = properties.start([dir('/etc')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 const b = permissions.start([dir('/etc')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 await properties.stop();
 await permissions.stop();
 refuse();
 assert.equal(await a, null);
 assert.equal(await b, null);
 assert.equal(permissions.jobId, null, 'the server never took the job, so there is no walk to name');
 assert.equal(properties.jobId, null);
 await permissions.stop();
 await properties.stop();
 assert.deepEqual(cancelled, [], 'and nothing is cancelled by guesswork');
});

// --- and the claim is one USER's (Astra r5 #6, Astra r6 #1) -------------------
//
// The register is module-level, so it survives the sign-in it was filled under.
// Alice's cancel goes unacknowledged and the claim stands; the page is then taken
// over by the administrator Bob, whose first dialog swept the register and resent
// Alice's cancel with Bob's token and Bob's credentials — which jobCancel allows,
// because an administrator may cancel another user's job.
//
// What scopes the claim is the OWNERSHIP EPOCH, not the session generation. The
// generation moves whenever the session object is replaced — a read-only toggle,
// the minute poll — and none of those mean Alice has gone away; keying the claim
// on it meant her own refresh disowned her running measurement (Astra r6 #1).

const stubborn = cancelled => ({
 report: () => {},
 track: () => {},
 cancel: async id => { cancelled.push(id); return false; },    // the wire is down: the claim stands
 poll: () => new Promise(() => {}),                            // the walk is still going
});

test('a claim made in one session is not retried after the page is switched to another user (Astra r5 #6)', async t => {
 resetSizeJobs();
 const posts = [], cancelled = [];
 mockFetch(t, posts, () => (posts.length > 1 ? 's2' : 's1'));
 update({session: {user: 'alice', uid: 1000}});                // Alice is signed in
 const alice = createSizeRunner(stubborn(cancelled));
 alice.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 await alice.stop();                                           // the dialog's close event
 assert.deepEqual(cancelled, ['s1'], 'the cancel was attempted');
 assert.equal(alice.jobId, 's1', 'unacknowledged, and still hers to retry while she is signed in');
 update({session: {user: 'administrator', uid: 0}});           // Bob takes the page over
 const bob = createSizeRunner(stubborn(cancelled));
 assert.equal(bob.jobId, null, 'Alice’s walk is not Bob’s to name');
 assert.equal(alice.jobId, null, 'nor is it named by the runner that asked, in somebody else’s session');
 await bob.stop();                                             // Bob opens Permissions and closes it
 assert.deepEqual(cancelled, ['s1'], 'and nothing is resent with Bob’s credentials');
 bob.start([dir('/share/Public')]);                            // Recount, on Bob's own folder
 await new Promise(resolve => setTimeout(resolve, 0));
 await bob.stop();
 assert.deepEqual(cancelled, ['s1', 's2'], 'Bob stops his own walk, and only his own');
 assert.equal(bob.jobId, 's2', 'which is unacknowledged, so it stays his to retry');
});

test('a claim made in the CURRENT session is still retried by the next dialog to act (Astra r5 #6)', async t => {
 resetSizeJobs();
 const posts = [], cancelled = [];
 mockFetch(t, posts);
 update({session: {user: 'alice', uid: 1000}});
 const properties = createSizeRunner(stubborn(cancelled)), permissions = createSizeRunner(stubborn(cancelled));
 properties.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 await properties.stop();
 assert.deepEqual(cancelled, ['s1'], 'the cancel was attempted');
 assert.equal(permissions.jobId, 's1', 'same session: the other dialog still names the walk');
 await permissions.stop();                                     // Stop in the dialog that never sent it
 assert.deepEqual(cancelled, ['s1', 's1'], 'and retries it — the ownership rule costs nothing here');
 assert.equal(properties.jobId, 's1', 'still unacknowledged, still named');
});

// A REFRESH is not a change of user, and Alice's session is refreshed for
// reasons that have nothing to do with her: settings.js re-reads it after a
// read-only toggle, app.js re-reads it every minute. Round 5 scoped the claim by
// the session generation, which moves on each of those — so a toggle arriving
// while her measurement ran made jobId null, and Stop and the close event let go
// of the walk without ever sending a cancel (Astra r6 #1).
test('a same-user session refresh does not disown a running measurement (Astra r6 #1)', async t => {
 resetSizeJobs();
 const posts = [], cancelled = [];
 mockFetch(t, posts);
 update({session: {user: 'alice', uid: 1000, readOnly: false}});
 const properties = createSizeRunner(stubborn(cancelled));
 properties.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 update({session: {user: 'alice', uid: 1000, readOnly: true}});   // the read-only toggle, in another tab
 assert.equal(properties.jobId, 's1', 'her own walk, still hers to stop');
 await properties.stop();                                         // the dialog's close event
 assert.deepEqual(cancelled, ['s1'], 'and the cancel really goes out');
 assert.equal(properties.jobId, 's1', 'unacknowledged, so it stays named for the next retry');
 update({session: {user: 'alice', uid: 1000, csrf: 'rotated'}});   // the minute poll, with a rotated token
 assert.equal(properties.jobId, 's1', 'a rotated token is not a new person either');
 await properties.stop();
 assert.deepEqual(cancelled, ['s1', 's1'], 'so Stop retries it');
});

test('signing out drops the claim rather than carrying it (Astra r6 #1)', async t => {
 resetSizeJobs();
 const posts = [], cancelled = [];
 mockFetch(t, posts);
 update({session: {user: 'alice', uid: 1000}});
 const properties = createSizeRunner(stubborn(cancelled));
 properties.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 await new Promise(resolve => setTimeout(resolve, 0));
 await properties.stop();
 assert.deepEqual(cancelled, ['s1'], 'the cancel was attempted');
 update({session: null});                                         // sign-out, or the 401 that api.js publishes
 assert.equal(properties.jobId, null, 'there is nobody here with standing to ask again');
 await properties.stop();
 assert.deepEqual(cancelled, ['s1'], 'and nothing is resent');
});

// --- the WAIT is owned by the same person as the claim (Astra r7 #3) ----------
//
// The claims moved to the ownership epoch in round 6; the poll did not, and the
// two then disagreed about whose walk it was. awaitJob uses sessionGuard, so a
// same-user refresh arriving during a GET /api/jobs/<id> made it answer null —
// which start() reads as "the measurement did not answer", so abandon() cancels
// the walk under a dialog that is still open, and start()'s own guard then
// suppresses the failure report it just caused. One cancel, no terminal report,
// "Measuring…" for ever (Astra r7 #3, reproduced with the real awaitJob).
//
// These two tests therefore use the REAL awaitJob, only hurried: the option
// props.js passes it is the whole of the fix, and a stub would not carry it.
const hurried = (id, options) => awaitJob(id, {...options, delay: 1, tries: 400});

// heldJobFetch answers the size POST at once and hands every single-job GET back
// to the test UNANSWERED, each with its own `reply`.
//
// The round-7 versions of these two tests let the mock answer immediately,
// landed the session change in the gap between two polls, waited a fixed 20 ms
// and read the outcome. That is not the scenario — r7 #3 is a change arriving
// DURING a GET — and the switch test was not decisive either: it accepted the
// wait ending however it ended, spending all 400 tries included, so both tests
// still passed against a jobs.js that ignored the guard option entirely
// (Astra r8 #3).
//
// Holding the GET open makes the boundary the test's to choose: the session
// changes while the request is genuinely in flight, and what is asserted
// afterwards is whether ANOTHER GET goes out — the one thing "still measuring"
// and "gave up" actually differ by.
function heldJobFetch(t, id = 's1') {
 const gets = [];
 t.mock.method(globalThis, 'fetch', async url => {
  if (String(url).endsWith('api/jobs/size')) return new Response(JSON.stringify({job: {id, state: 'queued'}}), {status: 202});
  return new Promise(resolve => gets.push({reply: job => resolve(new Response(JSON.stringify({job}), {status: 200}))}));
 });
 return gets;
}
// turn yields to the event loop, and to the 1 ms sleeps inside the hurried poll,
// without asserting anything about how long anything takes.
const turn = (ms = 2) => new Promise(resolve => setTimeout(resolve, ms));
// untilGets waits for the Nth poll to be ISSUED, and says what is missing rather
// than hanging until the runner's timeout.
async function untilGets(gets, n, what) {
 for (let i = 0; i < 60 && gets.length < n; i++) await turn();
 assert.equal(gets.length, n, what);
}

test('a same-user refresh during the poll neither cancels the walk nor loses its answer (Astra r7 #3)', async t => {
 resetSizeJobs();
 const cancelled = [], reports = [];
 const gets = heldJobFetch(t);
 update({session: {user: 'alice', uid: 1000, readOnly: false}});
 const runner = createSizeRunner({
  report: r => reports.push(r), track: () => {},
  cancel: async id => { cancelled.push(id); return true; },
  poll: hurried,
 });
 const measuring = runner.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 await untilGets(gets, 1, 'the first poll is on the wire');
 update({session: {user: 'alice', uid: 1000, readOnly: true}});    // the toggle, in another tab, while it is
 gets[0].reply({id: 's1', state: 'running'});                      // and the du is still walking
 await untilGets(gets, 2, 'the wait polls again rather than giving up on her');
 assert.deepEqual(cancelled, [], 'a refresh is not a reason to stop measuring');
 assert.equal(runner.jobId, 's1', 'and the walk is still hers to stop');
 assert.equal(reports.at(-1).state, 'running', 'the dialog is still honestly measuring');
 gets[1].reply({id: 's1', state: 'done', result: {bytes: 2048, files: 3, dirs: 2}});   // the du finishes
 const job = await measuring;
 assert.equal(job?.state, 'done');
 assert.equal(reports.at(-1).state, 'done', 'and the answer really arrives');
 assert.equal(reports.at(-1).result.bytes, 2048);
 assert.equal(runner.jobId, null, 'a finished measurement has nothing left to stop');
});

// A switch is the other half of the same rule: the page is somebody else's now,
// so the wait is given up, nothing is reported into the new user's dialog — and
// nothing is cancelled either, because the walk is Alice's and this page now
// holds Bob's credentials (Astra r5 #6). The measurement is dropped from the
// shared cache rather than left as an answer Bob could attach to.
//
// Both halves are asserted here, in the order they happen: the refresh must not
// end the wait, and the switch must end it AT ONCE — not eventually, and not by
// running out of tries. Counting the polls is what tells those apart.
test('a user switch during the poll abandons the measurement and reports nothing (Astra r7 #3)', async t => {
 resetSizeJobs();
 const cancelled = [], reports = [];
 const gets = heldJobFetch(t);
 update({session: {user: 'alice', uid: 1000}});
 const runner = createSizeRunner({
  report: r => reports.push(r), track: () => {},
  cancel: async id => { cancelled.push(id); return true; },
  poll: hurried,
 });
 const measuring = runner.start([dir('/share/CACHEDEV1_DATA/_IMAGES')]);
 await untilGets(gets, 1, 'the first poll is on the wire');
 update({session: {user: 'alice', uid: 1000, readOnly: true}});    // a refresh first: her walk survives it
 gets[0].reply({id: 's1', state: 'running'});
 await untilGets(gets, 2, 'as it must');
 update({session: {user: 'administrator', uid: 0}});               // Bob takes the page over, mid-GET
 gets[1].reply({id: 's1', state: 'running'});                      // Alice's answer, arriving at Bob's page
 assert.equal(await measuring, null, 'the wait is given up');
 await turn(10);                                                   // ten times the poll's own sleep
 assert.equal(gets.length, 2, 'and NOT ONE further poll goes out for a page that is no longer hers');
 assert.equal(reports.at(-1).state, 'running', 'nothing is reported into Bob’s page');
 assert.equal(runner.jobId, null, 'Alice’s walk is not Bob’s to name');
 assert.deepEqual(cancelled, [], 'nor to cancel with Bob’s credentials (Astra r5 #6)');
});

test('a measurement that could not be submitted is not cached as an answer', async t => {
 resetSizeJobs();
 const {runner, reports} = harness();
 t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({error: {code: 'protected', message: 'no'}}), {status: 403}));
 assert.equal(await runner.start([dir('/etc')]), null);
 assert.equal(reports.at(-1).state, 'failed');
 // The next attempt really tries again rather than replaying the failure.
 const posts = [];
 mockFetch(t, posts);
 const second = await runner.start([dir('/etc')]);
 assert.equal(posts.length, 1);
 assert.equal(second.state, 'done');
 runner.stop();
});
