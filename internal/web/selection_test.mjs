// Run with: node internal/web/selection_test.mjs
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

const {selectionEntries}=await import('./static/js/list.js');
const {update,state}=await import('./static/js/state.js');

function fullPage(pageNo,size=500,total=3000) {
 return {entries:Array.from({length:size},(_,i) => ({name:`item${pageNo*size+i}`,path:`/item${pageNo*size+i}`,type:'file',size:0,mtime:0})),total,limit:size,path:'/',parent:'/'};
}

function setupSelection(indices) {
 // Page 0 loaded; total spans several unloaded pages.
 const pages=new Map();
 pages.set(0,fullPage(0).entries);
 update({session:{csrf:'C',family:'t'},total:3000,pages,selection:new Set(indices),exclude:false,generation:1});
}

test('selectionEntries refuses rather than silently truncating when a page cannot fill the selection', async t => {
 t.after(() => update({session:null,pages:new Map(),selection:new Set()}));
 setupSelection([1,2500]);
 // The server returns an EMPTY page 5, so index 2500 never loads.
 globalThis.fetch=async () => new Response(JSON.stringify({entries:[],total:3000,limit:500,path:'/',parent:'/'}),{status:200});
 await assert.rejects(selectionEntries(),/still loading|changed/i,'must refuse a partial selection, never return a truncated set');
});

test('selectionEntries fetches the missing page and returns the full selection', async t => {
 t.after(() => update({session:null,pages:new Map(),selection:new Set()}));
 setupSelection([1,2500]);
 globalThis.fetch=async url => {
  const offset=Number(new URL(url,'http://localhost/').searchParams.get('offset'));
  return new Response(JSON.stringify(fullPage(offset/500)),{status:200});
 };
 const entries=await selectionEntries();
 assert.equal(entries.length,2);
 assert.equal(entries[0].path,'/item1');
 assert.equal(entries[1].path,'/item2500');
});

test('selectionEntries returns null in select-all (exclude) mode', async t => {
 t.after(() => update({session:null,exclude:false}));
 update({session:{csrf:'C'},exclude:true,selection:new Set()});
 assert.equal(await selectionEntries(),null);
});
