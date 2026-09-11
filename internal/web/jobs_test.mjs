// Run with: node --test internal/web/jobs_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {formatBytes,formatRate,formatETA,jobPercent,jobDetailLine,shouldPoll,jobLive,createPoller} from './static/js/jobs.js';

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

test('a poll that arrives after stop does not restart the loop', async () => {
 const timers = fakeTimers();
 const poller = createPoller({load:async () => true,timers});
 poller.start();
 const pending = timers.run();
 poller.stop();
 await pending;
 assert.equal(poller.running,false);
});
