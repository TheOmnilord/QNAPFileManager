// Run with: node --test internal/web/selection_test.mjs
//
// selectionEntries is the one door every multi-item action goes through —
// Delete, Copy, Move, Permissions and the archive download — so what it hands
// back IS what those actions act on (stabilization contract §3.1, §3.4, §3.5).
import assert from 'node:assert/strict';
import {test} from 'node:test';

// selectionEntries fetches unloaded pages through page()/api()/fetch and touches
// no DOM (render() early-returns without a layout), so a tiny document double is
// enough.
class El { constructor() { this.listeners={}; } addEventListener(){} }
const store=new Map();
const get=sel => { if (!store.has(sel)) store.set(sel,new El()); return store.get(sel); };
globalThis.document={querySelector:get,createElement:()=>new El(),addEventListener(){},getElementById(){return undefined;}};
globalThis.window={addEventListener(){}};
globalThis.matchMedia=()=>({matches:false});
globalThis.location={hash:''};

const {
 selectionEntries,loadList,entryAt,DEFAULT_PAGE,
 pruneSelection,resolveSelection,selectionPairs,settleSelection,
}=await import('./static/js/list.js');
const {update,state}=await import('./static/js/state.js');
const {MAX_ROOTS,tooManySentence}=await import('./static/js/why.js');

// b64 is the byte-safe encoding the server uses for pathB64.
const b64=bytes => Buffer.from(bytes,'binary').toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const item=n => ({name:`item${n}`,path:`/item${n}`,type:'file',size:0,mtime:0});
function fullPage(pageNo,size=500,total=3000) {
 return {entries:Array.from({length:size},(_,i) => item(pageNo*size+i)),total,limit:size,path:'/',parent:'/'};
}
const json=body => new Response(JSON.stringify(body),{status:200});
const offsetOf=url => Number(new URL(url,'http://localhost/').searchParams.get('offset'));

// listing loads a 3,000-entry folder the way the app does — through loadList, so
// the page size is the one the SERVER answered with (500 here), not the client's
// request — and leaves page 0 loaded and pages 1–5 not.
async function listing(t) {
 t.after(() => update({session:null,pages:new Map(),selection:new Map(),filter:'',total:0}));
 update({session:{csrf:'C',family:'t'},path:'/',pathB64:'',filter:''});
 globalThis.fetch=async url => json(fullPage(offsetOf(url)/500));
 await loadList();
 assert.equal(state.pages.size,1,'only the first page is loaded for a folder past 2,000 entries');
 assert.equal(state.total,3000);
}

// --- §3.2: one response for ordinary folders ----------------------------------

test('the first request asks for 2,000 entries, so a folder of up to 2,000 is one response', async t => {
 t.after(() => update({session:null,pages:new Map(),selection:new Map(),total:0}));
 assert.equal(DEFAULT_PAGE,2000);
 update({session:{csrf:'C',family:'t'},path:'/',pathB64:'',filter:''});
 const asked=[];
 globalThis.fetch=async url => {
  const q=new URL(url,'http://localhost/').searchParams;
  asked.push([q.get('offset'),q.get('limit')]);
  return json({entries:Array.from({length:2000},(_,i) => item(i)),total:2000,limit:2000,path:'/',parent:'/'});
 };
 await loadList();
 assert.deepEqual(asked,[['0','2000']]);
 assert.equal(state.pages.size,1);
 assert.equal(state.pages.get(0).length,2000);
});

test('a server that answers with a smaller page is followed, not overruled', async t => {
 t.after(() => update({session:null,pages:new Map(),selection:new Map(),total:0}));
 update({session:{csrf:'C',family:'t'},path:'/',pathB64:'',filter:''});
 const asked=[];
 globalThis.fetch=async url => {
  const q=new URL(url,'http://localhost/').searchParams;
  asked.push([q.get('offset'),q.get('limit')]);
  const offset=Number(q.get('offset'));
  return json({entries:Array.from({length:Math.min(500,1500-offset)},(_,i) => item(offset+i)),total:1500,limit:500,path:'/',parent:'/'});
 };
 await loadList();
 // Its listMax is 500: the rest of a folder this size is still loaded at once,
 // in the server's page size.
 assert.deepEqual(asked,[['0','2000'],['500','500'],['1000','500']]);
 assert.equal(entryAt(1499).path,'/item1499');
});

test('selectionEntries refuses rather than silently truncating when a page cannot fill the selection', async t => {
 await listing(t);
 // Row 2500 was chosen by a Shift range before its page arrived: index only.
 update({selection:new Map([[1,entryAt(1)],[2500,null]])});
 // The server returns an EMPTY page 5, so index 2500 never loads.
 globalThis.fetch=async () => json({entries:[],total:3000,limit:500,path:'/',parent:'/'});
 await assert.rejects(selectionEntries(),/still loading|changed/i,'must refuse a partial selection, never return a truncated set');
});

test('selectionEntries fetches the missing page and returns the full selection', async t => {
 await listing(t);
 update({selection:new Map([[1,entryAt(1)],[2500,null]])});
 globalThis.fetch=async url => json(fullPage(offsetOf(url)/500));
 const entries=await selectionEntries();
 assert.equal(entries.length,2);
 assert.equal(entries[0].path,'/item1');
 assert.equal(entries[1].path,'/item2500');
 // The row is settled in the selection itself, not only in the answer.
 assert.equal(state.selection.get(2500)?.path,'/item2500');
});

test('an action acts on the selection as it was when it was asked for, not as it is when its pages arrive', async t => {
 await listing(t);
 update({selection:new Map([[1,entryAt(1)],[2500,null]])});
 let release;
 const held=new Promise(resolve => { release=resolve; });
 globalThis.fetch=async url => { await held; return json(fullPage(offsetOf(url)/500)); };
 const pending=selectionEntries();
 // A click while page 5 is still on its way: a new selection, for the NEXT action.
 update({selection:new Map([[3,entryAt(3)]])});
 release();
 assert.deepEqual((await pending).map(e => e.path),['/item1','/item2500']);
 assert.deepEqual([...state.selection.keys()],[3],'and the new selection is left as the user made it');
});

test('a bare Set of indices — the old shape — still resolves through the pages', async t => {
 await listing(t);
 update({selection:new Set([1,2500])});
 globalThis.fetch=async url => json(fullPage(offsetOf(url)/500));
 assert.deepEqual((await selectionEntries()).map(e => e.path),['/item1','/item2500']);
});

test('select-all (exclude) mode is gone, and an empty selection is an empty answer, never null', async t => {
 await listing(t);
 assert.equal('exclude' in state,false,'state no longer carries the exclude flag');
 assert.ok(state.selection instanceof Map);
 update({selection:new Map()});
 assert.deepEqual(await selectionEntries(),[]);
});

// --- §3.5: never more than MAX_ROOTS ------------------------------------------

test('a selection past MAX_ROOTS is refused in the table’s sentence, before anything is fetched', async t => {
 await listing(t);
 assert.equal(MAX_ROOTS,1000);
 const many=new Map();
 for (let i=0;i<MAX_ROOTS+1;i++) many.set(i,i<500 ? entryAt(i) : null);   // most of them on unloaded pages
 update({selection:many});
 let requests=0;
 globalThis.fetch=async url => { requests++; return json(fullPage(offsetOf(url)/500)); };
 await assert.rejects(selectionEntries(),err => {
  assert.equal(err.message,tooManySentence(MAX_ROOTS+1));
  assert.equal(err.message,`Select at most ${(1000).toLocaleString()} items at a time (${(1001).toLocaleString()} are selected).`);
  return true;
 });
 assert.equal(requests,0,'a refused selection costs no page reads');
});

test('exactly MAX_ROOTS is carried in full', async t => {
 await listing(t);
 const many=new Map();
 for (let i=0;i<MAX_ROOTS;i++) many.set(i,i<500 ? entryAt(i) : null);
 update({selection:many});
 globalThis.fetch=async url => json(fullPage(offsetOf(url)/500));
 const entries=await selectionEntries();
 assert.equal(entries.length,MAX_ROOTS);
 assert.equal(entries.at(-1).path,`/item${MAX_ROOTS-1}`);
});

// --- §3.1: concrete references ------------------------------------------------

test('the selection’s entries are the ones DISPLAYED, whatever the listing says later', async t => {
 await listing(t);
 const shown=[entryAt(3),entryAt(4)];
 update({selection:new Map([[3,shown[0]],[4,shown[1]]])});
 // The listing is read again and the folder has changed: the same indices now
 // name different files. An index-based resolution would act on those.
 const later=fullPage(0).entries.map((e,i) => ({...e,name:`other${i}`,path:`/other${i}`}));
 update({pages:new Map([[0,later]])});
 assert.equal(entryAt(3).path,'/other3','the listing has moved on');
 const entries=await selectionEntries();
 assert.deepEqual(entries.map(e => e.path),['/item3','/item4'],'the action acts on what the user saw');
 assert.equal(entries[0],shown[0],'the very objects that were on the screen');
});

// --- §3.4: duplicates and hidden rows -----------------------------------------

test('duplicate references (same path bytes) are dropped, lookalikes are not', async t => {
 await listing(t);
 const raw='/share/\xff';
 const byBytes={name:'�',path:'/share/�',pathB64:b64(raw),type:'file'};
 const sameBytes={name:'�',path:'/share/�',pathB64:b64(raw),type:'file'};
 // Displays exactly like the two above, but IS the three bytes of U+FFFD.
 const lookalike={name:'�',path:'/share/�',type:'file'};
 // A page boundary that re-read a changed folder shows /item7 twice.
 update({selection:new Map([[7,entryAt(7)],[8,{...entryAt(7)}],[10,byBytes],[11,sameBytes],[12,lookalike]])});
 const entries=await selectionEntries();
 assert.deepEqual(entries.map(e => e.path),['/item7','/share/�','/share/�']);
 assert.equal(entries[1],byBytes,'the first of two references to one file is the one kept');
 assert.equal(entries[2],lookalike,'a different file that only LOOKS the same is not a duplicate');
});

test('selectionEntries never returns a hidden row', async t => {
 await listing(t);
 update({filter:'item25'});
 // Row 2500 (item2500) matches; row 2600 (item2600) does not, and was chosen
 // before its page — or the filter — arrived.
 update({selection:new Map([[2500,null],[2600,null]])});
 globalThis.fetch=async url => json(fullPage(offsetOf(url)/500));
 const entries=await selectionEntries();
 assert.deepEqual(entries.map(e => e.path),['/item2500']);
 assert.deepEqual([...state.selection.keys()],[2500],'the hidden row leaves the selection too, so the count is honest');
 // A row selected while visible and hidden since — without the filter handler
 // having pruned it — is not returned either.
 update({filter:'',selection:new Map([[1,entryAt(1)],[2,entryAt(2)]])});
 update({filter:'item2'});
 assert.deepEqual((await selectionEntries()).map(e => e.path),['/item2']);
});

// --- the pure rules, one by one -----------------------------------------------

const visible=e => !e.hidden;

test('selectionPairs reads a Map in listing order and a Set as rows not yet known', () => {
 assert.deepEqual(selectionPairs(new Map([[5,'e'],[1,'a']])),[[1,'a'],[5,'e']]);
 assert.deepEqual(selectionPairs(new Set([3,1])),[[1,null],[3,null]]);
 assert.deepEqual(selectionPairs(null),[]);
});

test('settleSelection gives pending rows their entries, drops hidden ones, and says when nothing changed', () => {
 const pages=new Map([[0,[{name:'a'},{name:'b',hidden:true}]]]);
 const selection=new Map([[0,null],[1,null],[7,null]]);
 const settled=settleSelection(selection,pages,2,visible);
 assert.deepEqual([...settled],[[0,{name:'a'}],[7,null]],'the hidden row is gone; the row whose page is absent waits');
 assert.equal(settleSelection(new Map([[0,{name:'a'}]]),pages,2,visible),null);
});

test('pruneSelection keeps what can be seen and what is still pending', () => {
 const a={name:'a'},b={name:'b',hidden:true};
 const selection=new Map([[0,a],[1,b],[2,null]]);
 assert.deepEqual([...pruneSelection(selection,visible)],[[0,a],[2,null]]);
 const clean=new Map([[0,a]]);
 assert.equal(pruneSelection(clean,visible),clean,'nothing hidden: the same object back');
});

test('resolveSelection refuses a pending row instead of returning part of a selection', () => {
 assert.equal(resolveSelection(new Map([[0,{name:'a',path:'/a'}],[1,null]]),visible),null);
 assert.deepEqual(resolveSelection(new Map([[1,{path:'/b'}],[0,{path:'/a'}]]),visible).map(e => e.path),['/a','/b']);
 // A reference with no bytes at all is kept rather than called a duplicate.
 assert.equal(resolveSelection(new Map([[0,{name:'x'}],[1,{name:'x'}]]),visible).length,2);
});
