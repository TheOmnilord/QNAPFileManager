// Run with: node internal/web/settings_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';

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
 initSettings(async () => false,() => assert.fail('a declined toggle installs no session'));
 const box=get('#setReadOnly');
 box.checked=true; // the user just ticked it
 await box.listeners.change({target:box});
 assert.equal(fetched,0,'declined toggle must send no request');
 assert.equal(box.checked,false,'declined toggle must revert the checkbox');
});

// The finding: the refreshed session was installed with update({session})
// directly, so paintBanners never ran and "Read-only mode — no changes can be
// made" stayed on screen after read-only had been turned off (and the bar stayed
// away after it was turned on). The bar and the state it describes are painted
// together or not at all, so the toggle installs the session the one way a
// session is ever installed (Astra r1 #11).
test('the refreshed session goes through showSession, so the banners repaint', async t => {
 t.after(() => update({session:null}));
 update({session:{csrf:'C',readOnly:true,canWrite:false}});
 elements.clear(); // fresh listeners
 const posts=[],installed=[];
 t.mock.method(globalThis,'fetch',async (url,opts) => {
  posts.push({url:String(url),method:opts?.method});
  return String(url).includes('api/settings')
   ? new Response(null,{status:204})
   : new Response(JSON.stringify({user:'sveinung',readOnly:false,canWrite:true}),{status:200});
 });
 initSettings(async () => true,session => installed.push(session));
 const box=get('#setReadOnly');
 box.checked=false; // turning read-only OFF
 await box.listeners.change({target:box});
 assert.ok(posts.some(p => p.url.includes('api/settings') && p.method==='POST'),'confirmed toggle must POST api/settings');
 assert.ok(posts.some(p => p.url.includes('api/session')),'the session is re-read after the change');
 assert.equal(installed.length,1,'exactly one session install, and it is showSession’s');
 assert.equal(installed[0].canWrite,true,'the state the banners are repainted from');
 assert.equal(installed[0].readOnly,false);
});

// The wiring itself, because the seam is only worth having if app.js uses it:
// initSettings has no default for showSession, and app.js is the single caller.
test('app.js hands initSettings the real showSession', () => {
 const source=readFileSync(new URL('./static/js/app.js',import.meta.url),'utf8');
 assert.match(source,/initSettings\(confirmDialog,showSession\)/,
  'a settings toggle that does not repaint the banners is the bug this closes');
 assert.match(source,/export function showSession\(/);
});
