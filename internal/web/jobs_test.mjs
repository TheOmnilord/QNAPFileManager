// Run with: node --test internal/web/jobs_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {formatBytes,formatRate,formatETA,jobPercent,jobBarState,jobDetailLine,shouldPoll,jobLive,createPoller,jobTransitions,seedJob,trackedStates} from './static/js/jobs.js';

test('formatBytes reads in binary units', () => {
 assert.equal(formatBytes(0),'0 B');
 assert.equal(formatBytes(999),'999 B');
 assert.equal(formatBytes(8.2*1024**3),'8.2 GiB');
 assert.equal(formatBytes(14.1*1024**3),'14.1 GiB');
 assert.equal(formatBytes(112*1024**2),'112 MiB'); // no pointless ".0" past 100
 assert.equal(formatBytes(-1),'—');
});

test('formatRate and formatETA say nothing when nothing is known', () => {
 assert.equal(formatRate(112*1024**2),'112 MiB/s');
 assert.equal(formatRate(0),'');
 assert.equal(formatETA(-1),'');   // the server's "unknown"
 assert.equal(formatETA(52),'~52 s left');
 assert.equal(formatETA(65),'~1 m 5 s left');
 assert.equal(formatETA(120),'~2 m left');
 assert.equal(formatETA(7200),'~2 h left');
});

test('jobPercent is null for an indeterminate job', () => {
 assert.equal(jobPercent({files:5,filesTotal:-1,bytes:0,bytesTotal:-1}),null);
 assert.equal(jobPercent({files:1,filesTotal:4,bytes:0,bytesTotal:-1}),25);
 assert.equal(jobPercent({files:0,filesTotal:-1,bytes:512,bytesTotal:1024}),50);
});

// Counts are grouped with toLocaleString, whose separator is the viewer's, so
// the expectations are built the same way rather than pinning one locale.
const n = value => value.toLocaleString();

test('jobDetailLine is the panel second line', () => {
 const line = jobDetailLine({state:'running',files:1204,filesTotal:3900,bytes:8.2*1024**3,bytesTotal:14.1*1024**3,rate:112*1024**2,eta:52});
 assert.equal(line,`${n(1204)} / ${n(3900)} files · 8.2 GiB / 14.1 GiB · 112 MiB/s · ~52 s left`);
});

test('jobDetailLine drops the denominator when the scan was capped', () => {
 const line = jobDetailLine({state:'running',files:412,filesTotal:-1,bytes:1024,bytesTotal:-1,rate:0,eta:-1});
 assert.equal(line,'412 files · 1 KiB');
});

test('jobDetailLine hides a stale ETA once the job is finished', () => {
 const line = jobDetailLine({state:'cancelled',files:412,filesTotal:8003,bytes:0,bytesTotal:0,rate:0,eta:52});
 assert.equal(line,`${n(412)} / ${n(8003)} files`);
});

test('jobDetailLine drops a zero total (a metadata job) instead of printing "/ 0"', () => {
 // Trash/restore/size jobs never set a files total, so it stays 0 — the bug was
 // "1 / 0 files". A finished job must not show a total of 0 nor a stale rate.
 const trash = jobDetailLine({state:'done',files:1,filesTotal:0,bytes:0,bytesTotal:0,rate:0,eta:0});
 assert.equal(trash,'1 files');
 const size = jobDetailLine({state:'done',files:36,filesTotal:0,bytes:6.3*1024**3,bytesTotal:0,rate:21.1*1024**3,eta:0});
 assert.equal(size,`36 files · 6.3 GiB`); // no "/ 0 B", no stale GiB/s
});

test('jobBarState makes a finished job determinate, never animating', () => {
 // done → full; a stopped job holds its fraction (or empty); a running job with
 // no denominator stays indeterminate (null value = the animated sweep).
 assert.equal(jobBarState({state:'done',files:1,filesTotal:0,bytes:0,bytesTotal:0}),100);
 assert.equal(jobBarState({state:'done',files:1,filesTotal:4,bytes:0,bytesTotal:0}),100);
 assert.equal(jobBarState({state:'cancelled',files:2,filesTotal:8,bytes:0,bytesTotal:0}),25);
 assert.equal(jobBarState({state:'failed',files:0,filesTotal:0,bytes:0,bytesTotal:0}),0);
 assert.equal(jobBarState({state:'running',files:1,filesTotal:4,bytes:0,bytesTotal:0}),25);
 assert.equal(jobBarState({state:'running',files:5,filesTotal:0,bytes:0,bytesTotal:0}),null); // indeterminate
});

test('polling follows the live states', () => {
 assert.equal(jobLive({state:'queued'}),true);
 assert.equal(jobLive({state:'running'}),true);
 for (const state of ['done','failed','cancelled']) assert.equal(jobLive({state}),false);
 assert.equal(shouldPoll([{state:'done'},{state:'running'}]),true);
 assert.equal(shouldPoll([{state:'done'},{state:'cancelled'}]),false);
 assert.equal(shouldPoll([]),false);
});

// A fake timer queue, so the loop is driven rather than waited for.
function fakeTimers() {
 const queue = new Map();
 let next = 1;
 return {
  setTimeout(fn) { queue.set(next,fn); return next++; },
  clearTimeout(handle) { queue.delete(handle); },
  size: () => queue.size,
  async run() { const [handle,fn] = [...queue][0]; queue.delete(handle); await fn(); },
 };
}

test('the poller keeps going while work is live and stops when it is not', async () => {
 const timers = fakeTimers();
 let calls = 0;
 const poller = createPoller({load:async () => { calls++; return calls < 3; },timers});
 poller.start();
 assert.equal(poller.running,true);
 await timers.run(); // 1st poll: still live, so another tick is scheduled
 assert.equal(poller.running,true);
 await timers.run(); // 2nd poll: still live
 assert.equal(poller.running,true);
 await timers.run(); // 3rd poll: idle, so the loop stops entirely
 assert.equal(poller.running,false);
 assert.equal(calls,3);
 assert.equal(timers.size(),0);
});

test('stopping the poller cancels the pending tick', async () => {
 const timers = fakeTimers();
 let calls = 0;
 const poller = createPoller({load:async () => { calls++; return true; },timers});
 poller.start();
 poller.stop();
 assert.equal(poller.running,false);
 assert.equal(timers.size(),0);
 assert.equal(calls,0);
});

// --- transitions (finding W8) -------------------------------------------------

const del = (id,state) => ({id,state,kind:'delete',title:'Moving to Trash: x'});

test('a job that finishes before the first poll is still a transition', () => {
 // The 202 seeds the submitted state, so the very first listing — which already
 // shows the job done — is a completion, not an unknown job to be skipped.
 trackedStates.clear();
 seedJob({id:'j1',state:'queued'});
 const {events,refresh} = jobTransitions([del('j1','done')],trackedStates);
 assert.equal(events.length,1);
 assert.equal(events[0].kind,'finished');
 assert.equal(refresh,true); // the list and the tree are reloaded
 trackedStates.clear();
});

test('a job first observed terminal counts as finished, and is announced once', () => {
 const seen = new Map();
 const first = jobTransitions([del('j2','done')],seen);
 assert.equal(first.events.length,1);
 assert.equal(first.refresh,true);
 // The same listing again is not a second transition.
 assert.deepEqual(jobTransitions([del('j2','done')],seen),{events:[],refresh:false});
});

test('the priming listing only records a baseline', () => {
 // Retained jobs from before this session opened must not announce themselves.
 const seen = new Map();
 assert.deepEqual(jobTransitions([del('old','done')],seen,{prime:true}),{events:[],refresh:false});
 assert.equal(seen.get('old'),'done');
 // A job submitted afterwards still transitions normally.
 const out = jobTransitions([del('old','done'),del('new','running')],seen);
 assert.equal(out.events.length,1);
 assert.equal(out.events[0].kind,'started');
});

test('a job that leaves the listing is forgotten', () => {
 const seen = new Map([['gone','done']]);
 jobTransitions([],seen);
 assert.equal(seen.size,0);
});

test('a size job finishing does not reload the file list', () => {
 const seen = new Map([['s1','running']]);
 const {events,refresh} = jobTransitions([{id:'s1',state:'done',kind:'size'}],seen);
 assert.equal(events.length,1);
 assert.equal(refresh,false);
});

test('a poll that arrives after stop does not restart the loop', async () => {
 const timers = fakeTimers();
 const poller = createPoller({load:async () => true,timers});
 poller.start();
 const pending = timers.run();
 poller.stop();
 await pending;
 assert.equal(poller.running,false);
});
