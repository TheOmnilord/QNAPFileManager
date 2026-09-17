// Run with: node --test internal/web/session_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {state,update,sessionGuard} from './static/js/state.js';
import {api} from './static/js/api.js';

test('session guards survive navigation but invalidate on every session assignment', () => {
 const session={user:'alice',csrf:'one'};
 update({session});
 const valid=sessionGuard();
 update({path:'/etc',generation:state.generation+1});
 assert.equal(valid(),true);
 const generation=state.sessionGeneration;
 update({session:null}); // Both sign-out and HTTP 401 use this update.
 assert.equal(state.sessionGeneration,generation+1);
 assert.equal(valid(),false);
 const signedOut=sessionGuard();
 update({session:null}); // Repeated expiry still invalidates pending connection work.
 assert.equal(signedOut(),false);
 update({session}); // Even the same identity/object cannot revive an old request.
 assert.equal(valid(),false);
 const reconnected=sessionGuard();
 update({session:{user:'bob',csrf:'two'}});
 assert.equal(reconnected(),false);
});

// The ownership epoch answers a different question from the generation: not
// "is this the same session object" but "is this still the same person's page".
// Long-lived ownership — props.js's unacknowledged size-job cancels — is scoped
// by it, because scoping by the generation meant a same-user refresh disowned a
// measurement the user was still watching (Astra r6 #1).
test('the ownership epoch moves on a sign-out or a change of user, never on a refresh', () => {
 update({session:{user:'alice',uid:1000,readOnly:false}});
 const mine=state.ownerEpoch,generation=state.sessionGeneration;
 update({session:{user:'alice',uid:1000,readOnly:true}});   // the read-only toggle
 assert.equal(state.ownerEpoch,mine,'a refresh is the same person');
 update({session:{user:'alice',uid:1000,csrf:'rotated'}});  // the minute poll
 assert.equal(state.ownerEpoch,mine);
 assert.equal(state.sessionGeneration,generation+2,'while the generation moved on each of those');
 update({session:{user:'alice',uid:1001}});                 // the same name, a different uid
 assert.equal(state.ownerEpoch,mine+1,'a switch is somebody else');
 update({session:null});
 assert.equal(state.ownerEpoch,mine+2,'and a sign-out is nobody');
});

test('delayed success and failure cannot publish after expiry and reauthentication', async () => {
 for (const reject of [false,true]) {
  update({session:{user:'alice'}});
  const valid=sessionGuard();
  let settle;
  const response=new Promise((resolve,fail) => { settle=reject ? fail : resolve; });
  const published=[];
  const continuation=(async () => {
   try {
    const data=await response;
    if (valid()) published.push(data);
   } catch(err) { if (valid()) published.push(err.message); }
  })();
  update({session:null});
  update({session:{user:'bob'}});
  settle(reject ? new Error('/alice/private') : {path:'/alice/private'});
  await continuation;
  assert.deepEqual(published,[]);
 }
});

test('api/session 401 shows the sign-in notice after the public shell loads', async t => {
 const originalDocument=globalThis.document;
 t.after(() => {
  if (originalDocument===undefined) delete globalThis.document;
  else globalThis.document=originalDocument;
 });
 const elements=new Map();
 const get=selector => {
  if (!elements.has(selector)) elements.set(selector,{hidden:true,textContent:'',replaceChildren(){}});
  return elements.get(selector);
 };
 globalThis.document={querySelector:get,querySelectorAll:() => []};
 update({session:null});
 t.mock.method(globalThis,'fetch',async (endpoint,options) => {
  assert.equal(endpoint,'api/session');
  assert.equal(options.credentials,'same-origin');
  return new Response(JSON.stringify({error:{message:'Sign in to QTS to continue.'}}),{status:401});
 });
 await assert.rejects(api('api/session'),/Sign in to QTS/);
 assert.equal(get('#signin').hidden,false);
 assert.equal(state.session,null);
 assert.match(get('#announce').textContent,/Sign in on the QTS desktop/);
});
