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

const {cancelJob, trackJob} = await import('./static/js/jobs.js');
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
 // The runner's retry is only as good as this answer. A service that replied —
 // even to say the job is gone — has stopped the walk or never had one; a
 // request that never left the machine has stopped nothing at all.
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
