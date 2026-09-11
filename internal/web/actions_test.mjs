// Run with: node --test internal/web/actions_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {runMutation, actionMessage} from './static/js/actions.js';
import {update} from './static/js/state.js';

test('runMutation drives the server confirmation-token flow', async t => {
 t.after(() => update({session:null}));
 const bodies=[];
 t.mock.method(globalThis,'fetch',async (url,opts) => {
  bodies.push(JSON.parse(opts.body));
  if (bodies.length===1) {
   return new Response(JSON.stringify({error:{code:'confirm_required',message:'needs confirm'},confirm:{token:'TOK',summary:{files:1}}}),{status:409});
  }
  return new Response(JSON.stringify({ok:true}),{status:200});
 });
 let asked=null;
 const res=await runMutation('api/fs/mkdir',{dir:'/etc/config',name:'x'},async (confirm,message) => { asked={confirm,message}; return true; });
 assert.deepEqual(res,{ok:true});
 assert.equal(asked.confirm.token,'TOK');
 assert.equal(asked.message,'needs confirm');
 assert.equal(bodies.length,2);
 assert.equal(bodies[1].confirm,'TOK'); // the re-post carries the token
 assert.equal(bodies[1].name,'x');      // and the identical original body
});

test('runMutation returns null when the confirmation is declined', async t => {
 t.after(() => update({session:null}));
 let posts=0;
 t.mock.method(globalThis,'fetch',async () => { posts++; return new Response(JSON.stringify({error:{code:'confirm_required',message:'m'},confirm:{token:'T'}}),{status:409}); });
 const res=await runMutation('api/fs/delete',{path:'/x'},async () => false);
 assert.equal(res,null);
 assert.equal(posts,1); // no second POST after a decline
});

test('runMutation rethrows a non-confirmable error', async t => {
 t.after(() => update({session:null}));
 t.mock.method(globalThis,'fetch',async () => new Response(JSON.stringify({error:{code:'protected',message:'no'}}),{status:403}));
 await assert.rejects(runMutation('api/fs/delete',{path:'/bin'},async () => true),err => { assert.equal(err.code,'protected'); return true; });
});

test('actionMessage names the hidden blockers on a not-empty delete', () => {
 const msg = actionMessage({code:'not_empty', blockers:[{name:'.@__thumb', hidden:true, dir:true}], truncated:false});
 assert.match(msg, /still inside: \.@__thumb/);
 assert.match(msg, /hidden items/);
});

test('actionMessage falls back to the code message when no blockers are present', () => {
 assert.match(actionMessage({code:'not_empty'}), /coming in a later version/);
 assert.match(actionMessage({code:'protected'}), /protected system path/);
});
