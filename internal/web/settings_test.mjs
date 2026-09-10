// Run with: node internal/web/settings_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';

// Minimal element/document doubles: initSettings only wires listeners and reads
// a handful of elements by id.
class El {
 constructor() { this.listeners={}; this.checked=false; this.hidden=false; this.textContent=''; }
 addEventListener(type,fn) { this.listeners[type]=fn; }
}
const elements=new Map();
const get=sel => { if (!elements.has(sel)) elements.set(sel,new El()); return elements.get(sel); };
globalThis.document={querySelector:get,createElement:()=>new El(),body:{append(){},},addEventListener(){}};

const {initSettings,readOnlyConfirmText}=await import('./static/js/settings.js');
const {update,state}=await import('./static/js/state.js');

test('readOnlyConfirmText distinguishes on and off', () => {
 assert.match(readOnlyConfirmText(false).body,/whole filesystem/i);
 assert.equal(readOnlyConfirmText(false).danger,true);
 assert.ok(!readOnlyConfirmText(true).danger);
});

test('read-only toggle requires a confirmation and sends nothing when declined', async t => {
 t.after(() => update({session:null}));
 update({session:{csrf:'C'}});
 let fetched=0;
 t.mock.method(globalThis,'fetch',async () => { fetched++; return new Response('{}',{status:200}); });
 // A confirm that always declines.
 initSettings(async () => false);
 const box=get('#setReadOnly');
 box.checked=true; // the user just ticked it
 await box.listeners.change({target:box});
 assert.equal(fetched,0,'declined toggle must send no request');
 assert.equal(box.checked,false,'declined toggle must revert the checkbox');
});

test('read-only toggle sends the change once confirmed', async t => {
 t.after(() => update({session:null}));
 update({session:{csrf:'C'}});
 elements.clear(); // fresh listeners
 const posts=[];
 t.mock.method(globalThis,'fetch',async (url,opts) => {
  posts.push({url:String(url),method:opts?.method});
  return new Response(JSON.stringify({readOnly:false,canWrite:true}),{status:200});
 });
 initSettings(async () => true);
 const box=get('#setReadOnly');
 box.checked=false; // turning read-only OFF
 await box.listeners.change({target:box});
 assert.ok(posts.some(p => p.url.includes('api/settings') && p.method==='POST'),'confirmed toggle must POST api/settings');
});
