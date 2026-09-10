// Run with: node --test internal/web/bootstrap_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {sessionQuery,cleanSessionURL,sessionBootstrap,transientAuthError} from './static/js/bootstrap.js';
import {api} from './static/js/api.js';

test('bootstrap forwards only the first SID and optional user, preserving encoding', () => {
 assert.deepEqual(sessionQuery('?sid=a%2Bb%26c%3D&user=alice%20smith&path=%2Fetc'),{sid:'a+b&c=',user:'alice smith'});
 assert.deepEqual(sessionQuery('?sid=first&sid=second&user='),{sid:'first',user:''});
 assert.deepEqual(sessionQuery('?sid='),{sid:''});
 assert.deepEqual(sessionQuery('?user=alice'),{});
 assert.deepEqual(sessionQuery(''),{});
});

test('cleanup removes every credential query field and preserves route and other parameters', () => {
 const href='https://nas/qnapfilemanager/?sid=secret&view=a%2Bb&user=alice&sid=again&user=bob#/etc';
 const clean=cleanSessionURL(href);
 assert.equal(clean,'/qnapfilemanager/?view=a%2Bb#/etc');
 assert.deepEqual(sessionQuery(new URL(clean,'https://nas').search),{});
 assert.equal(cleanSessionURL('https://nas/qnapfilemanager/?sid=secret&user=alice#/share'),'/qnapfilemanager/#/share');
 assert.equal(cleanSessionURL('https://nas/qnapfilemanager/#/share'),'/qnapfilemanager/#/share');
});

test('capture scrubs history before authentication; transient retries retain credentials until success', async () => {
 const calls=[],delays=[];
 let cleaned=false;
 const failures=[{status:503},{status:504},{network:true}];
 const connect=sessionBootstrap('https://nas/qnapfilemanager/?sid=a%2Bb&user=dev&view=list#/etc',url => {
  assert.equal(url,'/qnapfilemanager/?view=list#/etc');
  cleaned=true;
 },async params => {
  assert.equal(cleaned,true);
  calls.push({...params});
  if (failures.length) throw failures.shift();
  return {authenticated:true};
 },async ms => delays.push(ms));
 assert.equal(cleaned,true); // No request, resolution, or rejection is needed.
 assert.deepEqual(await connect(),{authenticated:true});
 assert.deepEqual(calls,Array.from({length:4},() => ({sid:'a+b',user:'dev'})));
 assert.deepEqual(delays,[250,500,1000]);
 await connect();
 assert.deepEqual(calls.at(-1),{});
});

test('Retry after transient exhaustion is bounded and never makes an anonymous request', async () => {
 const calls=[],delays=[];
 const connect=sessionBootstrap('https://nas/?sid=secret',() => {},async params => {
  calls.push({...params});
  throw {status:503};
 },async ms => delays.push(ms));
 for (let click=0; click<3; click++) {
  await assert.rejects(connect(),err => {
   assert.equal(transientAuthError(err),true);
   assert.match(err.message,/temporarily unavailable/);
   assert.doesNotMatch(err.message,/session.*ended/i);
   return true;
  });
 }
 assert.deepEqual(calls,Array.from({length:4},() => ({sid:'secret'})));
 assert.deepEqual(delays,[250,500,1000]);
});

test('definitive 401 and 429 clear credentials without retries', async () => {
 for (const status of [401,429]) {
  const calls=[];
  const connect=sessionBootstrap('https://nas/?sid=secret',() => {},async params => {
   calls.push({...params});
   if (calls.length===1) throw {status};
   return {authenticated:false};
  },async () => assert.fail('definitive errors must not retry'));
  await assert.rejects(connect(),err => err.status===status);
  await connect();
  assert.deepEqual(calls,[{sid:'secret'},{}]);
 }
});

test('expiry during backoff prevents further credential requests', async () => {
 let valid=true,calls=0;
 const connect=sessionBootstrap('https://nas/?sid=secret',() => {},async () => {
  calls++;
  throw {status:504};
 },async () => { valid=false; });
 assert.equal(await connect(() => valid),null);
 assert.equal(calls,1);
});

test('API exposes transient HTTP and network failures to bootstrap without a DOM', async t => {
 for (const status of [503,504,429]) {
  for (const body of ['<html>proxy failure</html>','null',JSON.stringify({error:{message:'Try again'}})]) {
   t.mock.method(globalThis,'fetch',async () => new Response(body,{status}));
   await assert.rejects(api('api/session'),err => {
    assert.equal(err.status,status);
    assert.equal(transientAuthError(err),status!==429);
    return true;
   });
  }
 }
 for (const failure of [new TypeError('offline'),new DOMException('timeout','TimeoutError')]) {
  t.mock.method(globalThis,'fetch',async () => { throw failure; });
  await assert.rejects(api('api/session'),err => transientAuthError(err));
 }
});
