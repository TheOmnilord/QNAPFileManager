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

test('definitive 401 clears credentials without retries', async () => {
 for (const status of [401]) {
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

test('429 retains SID and honors bounded Retry-After through API errors', async t => {
 t.mock.method(Date,'now',() => Date.parse('Thu, 10 Sep 2026 12:00:00 GMT'));
 for (const [retryAfter,delay] of [
  ['1',1000],['60',5000],['0',0],[null,250],['invalid',250],['-1',250],
  ['Thu, 10 Sep 2026 12:00:02 GMT',2000],['Thu, 10 Sep 2026 12:01:00 GMT',5000]
 ]) {
  for (const body of ['<html>busy</html>',JSON.stringify({error:{message:'Try again'}})]) {
   const calls=[],delays=[];
   t.mock.method(globalThis,'fetch',async url => {
    calls.push(url);
    return calls.length===1 ? new Response(body,{status:429,headers:retryAfter===null ? {} : {'Retry-After':retryAfter}}) :
     new Response(JSON.stringify({authenticated:true}));
   });
   const connect=sessionBootstrap('https://nas/?sid=secret&user=alice',() => {},
    params => api('api/session',params),async ms => delays.push(ms));
   assert.deepEqual(await connect(),{authenticated:true});
   assert.deepEqual(calls,['api/session?sid=secret&user=alice','api/session?sid=secret&user=alice']);
   assert.deepEqual(delays,[delay]);
   await connect();
   assert.equal(calls.at(-1),'api/session');
  }
 }
});

test('429 exhaustion remains terminal for a pending SID, including an empty SID', async () => {
 for (const sid of ['secret','']) {
  const calls=[],delays=[];
  const connect=sessionBootstrap(`https://nas/?sid=${sid}`,() => {},async params => {
   calls.push({...params});
   throw {status:429,retryAfter:'1'};
  },async ms => delays.push(ms));
  await assert.rejects(connect(),/Reopen QNAPFileManager/);
  await assert.rejects(connect(),/Reopen QNAPFileManager/);
  assert.deepEqual(calls,Array.from({length:4},() => ({sid})));
  assert.deepEqual(delays,[1000,1000,1000]);
 }
});

test('cookie Retry starts a fresh bounded attempt after exhaustion, including after SID success', async () => {
 for (const initialSID of [false,true]) {
  const calls=[],delays=[];
  let recovered=false;
  const connect=sessionBootstrap('https://nas/'+(initialSID ? '?sid=secret' : ''),() => {},async params => {
   calls.push({...params});
   if (Object.hasOwn(params,'sid') || recovered) return {authenticated:true};
   throw {status:503};
  },async ms => delays.push(ms));
  if (initialSID) await connect();
  for (let click=0; click<2; click++) await assert.rejects(connect(),/Please retry/);
  assert.deepEqual(calls.slice(initialSID ? 1 : 0),Array.from({length:8},() => ({})));
  assert.deepEqual(delays,[250,500,1000,250,500,1000]);
  recovered=true;
  assert.deepEqual(await connect(),{authenticated:true});
  assert.deepEqual(calls.at(-1),{});
 }
});

test('non-authentication errors do not discard a pending SID', async () => {
 const calls=[];
 const connect=sessionBootstrap('https://nas/?sid=secret',() => {},async params => {
  calls.push({...params});
  if (calls.length===1) throw {status:500};
  return {authenticated:true};
 },async () => assert.fail('unexpected retry'));
 await assert.rejects(connect(),err => err.status===500);
 assert.deepEqual(await connect(),{authenticated:true});
 assert.deepEqual(calls,[{sid:'secret'},{sid:'secret'}]);
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
    assert.equal(transientAuthError(err),true);
    return true;
   });
  }
 }
 for (const failure of [new TypeError('offline'),new DOMException('timeout','TimeoutError')]) {
  t.mock.method(globalThis,'fetch',async () => { throw failure; });
  await assert.rejects(api('api/session'),err => transientAuthError(err));
 }
});
