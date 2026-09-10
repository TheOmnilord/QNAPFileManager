import assert from 'node:assert/strict';
import {test} from 'node:test';
import {api} from './static/js/api.js';
import {state,update,sessionGuard} from './static/js/state.js';
import {sessionBootstrap} from './static/js/bootstrap.js';

test('QTS unavailable shows a transient notice without clearing authenticated state', async t => {
 const originalDocument=globalThis.document;
 t.after(() => {
  if (originalDocument===undefined) delete globalThis.document;
  else globalThis.document=originalDocument;
  update({session:null});
 });
 const elements=new Map();
 const get=selector => {
  if (!elements.has(selector)) elements.set(selector,{hidden:true,textContent:''});
  return elements.get(selector);
 };
 globalThis.document={querySelector:get};
 const session={user:'dev',csrf:'existing'},pages=new Map([[0,['private file']]]),selection=new Set(['selected']);
 update({session,pages,selection});
 const valid=sessionGuard();
 t.mock.method(globalThis,'fetch',async () => new Response(JSON.stringify({error:{
  code:'qts_unavailable',message:'QTS authentication is temporarily unavailable.'
 }}),{status:503,headers:{'Retry-After':'2'}}));
 await assert.rejects(api('api/fs/list'),err => {
  assert.equal(err.status,503);
  assert.equal(err.code,'qts_unavailable');
  assert.equal(err.retryAfter,'2');
  assert.equal(err.transient,true);
  return true;
 });
 assert.equal(state.session,session);
 assert.equal(state.pages,pages);
 assert.equal(state.selection,selection);
 assert.equal(valid(),true);
 assert.equal(get('#signin').hidden,false);
 assert.equal(get('#signin h2').textContent,'QTS temporarily unavailable');
});

test('QTS outage bootstrap retries the same SID and honors Retry-After', async t => {
 update({session:null});
 const calls=[],delays=[];
 t.mock.method(globalThis,'fetch',async url => {
  calls.push(url);
  return calls.length===1 ? new Response(JSON.stringify({error:{code:'qts_unavailable',message:'Try again.'}}),
   {status:503,headers:{'Retry-After':'2'}}) : new Response(JSON.stringify({authenticated:true}));
 });
 const connect=sessionBootstrap('https://nas/?sid=new&user=dev',() => {},
  params => api('api/session',params),async ms => delays.push(ms));
 assert.deepEqual(await connect(),{authenticated:true});
 assert.deepEqual(calls,['api/session?sid=new&user=dev','api/session?sid=new&user=dev']);
 assert.deepEqual(delays,[2000]);
});
