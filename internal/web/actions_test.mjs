// Run with: node --test internal/web/actions_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {runMutation, actionMessage, onNewFolderError, deleteGrade, trashOutcome, undoRestore, PERMANENT_WARNING} from './static/js/actions.js';
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
 assert.match(actionMessage({code:'not_empty'}), /removes a folder and its contents/);
 assert.match(actionMessage({code:'protected'}), /protected system path/);
 assert.match(actionMessage({code:'no_trash'}), /no Trash on this volume/);
});

test('actionMessage explains the owner_unset partial state (finding E)', () => {
 // The folder was created but could not be chowned to the user; the message says
 // it exists and is system-owned rather than reading as a flat failure.
 const msg = actionMessage({code:'owner_unset'});
 assert.match(msg, /created but could not be assigned to you/);
 assert.match(msg, /check it or delete it/);
});

test('onNewFolderError refreshes the listing before reporting (finding E)', () => {
 // mkdir can fail AFTER the folder was created (owner_unset, or a detected
 // concurrent change), so the failure path must still re-list so the
 // created-but-not-adopted folder becomes visible — and it must refresh BEFORE
 // the error is reported. No rollback happens here.
 const calls=[];
 const err={code:'owner_unset',message:'stuck'};
 onNewFolderError(err,{refresh:()=>calls.push('refresh'),report:e=>calls.push(['report',e])});
 assert.deepEqual(calls,[ 'refresh', ['report',err] ]);
});

test('deleteGrade is the confirmation ladder', () => {
 // A move to Trash is reversible: grade 1, a simple confirm.
 assert.equal(deleteGrade({mode:'trash',summary:{files:3,bytes:100}}),1);
 assert.equal(deleteGrade({mode:'trash',summary:null}),1);
 // A permanent delete is grade 2 (typed phrase) whatever the summary says.
 assert.equal(deleteGrade({mode:'permanent',summary:{files:1,bytes:0}}),2);
 // …and so is a trash delete the server warned about, at scale, or in a
 // warn-class location.
 assert.equal(deleteGrade({mode:'trash',summary:{warnings:[PERMANENT_WARNING]}}),2);
 assert.equal(deleteGrade({mode:'trash',summary:{warnings:['Inside a protected system path.']}}),2);
 assert.equal(deleteGrade({mode:'trash',summary:{files:101}}),2);
 assert.equal(deleteGrade({mode:'trash',summary:{bytes:(1<<30)+1}}),2);
});

// --- the Undo toast (finding W9) ---------------------------------------------

test('Undo is offered only for a job that actually reached Trash', () => {
 // Still running (or queued): nothing to undo yet, and nothing claimed.
 assert.deepEqual(trashOutcome(null,3),{ids:[],message:'Still moving 3 item(s) to Trash — see Operations.'});
 // Finished: the count is the worker's own ids, not what was requested.
 const done = trashOutcome({state:'done',result:{trashIds:['1-a','2-b']}},2);
 assert.deepEqual(done.ids,['1-a','2-b']);
 assert.equal(done.message,'Moved 2 item(s) to Trash');
 // Finished with no ids (an older worker, the fallback found nothing): the
 // message still reports the delete, but there is no Undo to offer.
 assert.deepEqual(trashOutcome({state:'done',result:{}},4),{ids:[],message:'Moved 4 item(s) to Trash'});
 // Failed with nothing moved: the job's own (code-derived) error, no Undo.
 assert.deepEqual(trashOutcome({state:'failed',error:'Read-only mode is on, so the operation was refused.'},1),
  {ids:[],message:'Read-only mode is on, so the operation was refused.'});
});

test('a failed-but-partial delete still offers Undo for what reached Trash (R3-WA2)', () => {
 // The job ended "failed" — one root was refused — but four entries really were
 // moved and the terminal result names them. Discarding those ids left the user
 // with a bare error and no way back; the restore endpoint re-validates every id
 // against the caller's own trash, so offering them is safe.
 const partial = trashOutcome({state:'failed',error:'This location is protected, so the operation was refused.',result:{trashIds:['1-a','2-b','3-c','4-d']}},5);
 assert.deepEqual(partial.ids,['1-a','2-b','3-c','4-d']);
 assert.equal(partial.message,'Moved 4 of 5 to Trash; 1 failed');
 // A result that names more ids than were requested never reports a negative
 // failure count.
 assert.equal(trashOutcome({state:'failed',result:{trashIds:['1-a','2-b']}},1).message,'Moved 2 of 1 to Trash; 0 failed');
});

test('a cancelled delete offers Undo for the part that did reach Trash', () => {
 const partial = trashOutcome({state:'cancelled',result:{trashIds:['1-a']}},5);
 assert.deepEqual(partial.ids,['1-a']);
 assert.equal(partial.message,'Cancelled — 1 of 5 item(s) reached Trash');
 assert.deepEqual(trashOutcome({state:'cancelled',result:{}},5),{ids:[],message:'Cancelled — nothing was moved to Trash'});
});

test('Undo restores exactly the ids the job reported', async t => {
 t.after(() => update({session:null}));
 const bodies=[];
 t.mock.method(globalThis,'fetch',async (url,opts) => {
  bodies.push({url:String(url),body:JSON.parse(opts.body)});
  return new Response(JSON.stringify({job:{id:'0123456789abcdef',state:'queued'}}),{status:202});
 });
 const job = await undoRestore(['1-a','2-b']);
 assert.equal(job.id,'0123456789abcdef');
 assert.equal(bodies.length,1);
 assert.match(bodies[0].url,/api\/trash\/restore$/);
 assert.deepEqual(bodies[0].body,{ids:['1-a','2-b']});
});

test('the permanent warning is the exact sentence the server sends', () => {
 // Pinned on both sides: web.permanentWarning in routes_jobs.go carries the
 // same text, and a Go test asserts it.
 assert.equal(PERMANENT_WARNING,'This delete is permanent and cannot be undone.');
});
