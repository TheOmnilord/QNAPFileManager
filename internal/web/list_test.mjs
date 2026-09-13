// Run with: node --test internal/web/list_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {initList,render,selectedOne,refreshToolbar,paintEmpty} from './static/js/list.js';
import {state,update} from './static/js/state.js';

// Minimal element doubles: no browser or DOM dependency required.
class Element {
 constructor() {
  this.children=[]; this.listeners={}; this.attrs={}; this.dataset={};
  this.scrollTop=0; this.clientHeight=360; this.classes=new Set();
  this.classList={
   toggle:(name,on) => on ? this.classes.add(name) : this.classes.delete(name),
   remove:name => this.classes.delete(name),
  };
 }
 setAttribute(key,value) {
  this.attrs[key]=String(value);
  if (key==='data-idx') this.dataset.idx=String(value);
  if (key==='tabindex') this.tabIndex=Number(value);
 }
 append(...children) { this.children.push(...children); }
 replaceChildren(...children) { this.children=children; }
 addEventListener(type,fn) { this.listeners[type]=fn; }
 querySelectorAll(selector) {
  assert.equal(selector,'[data-idx]');
  return this.children.filter(row => row.dataset.idx !== undefined);
 }
 contains(element) { return this.children.includes(element); }
 closest() { return null; }
 focus() { document.activeElement=this; this.listeners.focus?.(); }
 showModal() { this.open=true; }
}
const elements=new Map();
const get=selector => {
 if (!elements.has(selector)) elements.set(selector,new Element());
 return elements.get(selector);
};
const sheet={href:'http://localhost/app.css',cssRules:[],insertRule() { this.cssRules.push({style:{}}); return this.cssRules.length-1; }};
globalThis.document={
 querySelector:get,
 createElement:() => new Element(),
 getElementById:id => get('#listRows').children.find(row => row.attrs.id===id),
 styleSheets:[sheet],addEventListener(){},activeElement:null,
};
globalThis.window={addEventListener(){}};
globalThis.matchMedia=() => ({matches:false});
globalThis.location={hash:''};
const requests=[];
globalThis.fetch=async url => {
 requests.push(new URL(url,'http://localhost/'));
 return {ok:true,status:200,json:async () => ({content:'preview',bytes:7,mode:'0644'})};
};
initList();

function setup(total=3) {
 const entries=Array.from({length:total},(_,i) => ({name:`item${i}`,path:`/item${i}`,type:i===0 ? 'dir' : 'file',size:0,mtime:0}));
 const pages=new Map();
 for (let i=0;i<total;i+=500) pages.set(i/500,entries.slice(i,i+500));
 update({session:{family:'test'},total,pages,selection:new Set(),exclude:false,focus:0,anchor:0,loading:false,filter:''});
 get('#listViewport').scrollTop=0;
 document.activeElement=null;
 render();
 return get('#listRows').children.slice();
}
const rowAt=index => document.getElementById(`row-${index}`);
async function key(key,modifiers={}) {
 get('#list').listeners.keydown({key,target:get('#list'),preventDefault(){},...modifiers});
 await new Promise(resolve => setImmediate(resolve));
}
function selection(row,on) {
 assert.equal(row.attrs['aria-selected'],String(on));
 assert.equal(row.classes.has('selected'),on);
}

test('desktop click sequences preserve row identity and double-click/Enter open folders and files', async () => {
 const rows=setup();
 for (const [index,row] of rows.entries()) {
  row.listeners.click({});
  assert.equal(rowAt(index),row);
  row.listeners.click({});
  assert.equal(rowAt(index),row);
  selection(row,true);
  assert.equal(row.tabIndex,0);
  assert.equal(document.activeElement,row);
  location.hash=''; requests.length=0;
  row.listeners.dblclick();
  if (index===0) assert.equal(location.hash,'#/item0');
  else assert.equal(requests.at(-1).searchParams.get('path'),`/item${index}`);
  location.hash=''; requests.length=0;
  await key('Enter');
  if (index===0) assert.equal(location.hash,'#/item0');
  else assert.equal(requests.at(-1).searchParams.get('path'),`/item${index}`);
 }
 rows.forEach((row,i) => assert.equal(rowAt(i),row));
});

test('Space, range arrows, focus-only arrows, select-all and Escape update existing rows', async () => {
 const rows=setup();
 rows[0].listeners.click({});
 await key(' '); selection(rows[0],false);
 await key(' '); selection(rows[0],true);
 await key('ArrowDown',{shiftKey:true});
 selection(rows[0],true); selection(rows[1],true);
 assert.equal(rows[0].tabIndex,-1); assert.equal(rows[1].tabIndex,0);
 assert.equal(document.activeElement,rows[1]);
 await key('ArrowDown',{ctrlKey:true});
 assert.equal(state.focus,2); selection(rows[2],false);
 assert.equal(rows[1].tabIndex,-1); assert.equal(rows[2].tabIndex,0);
 await key('a',{ctrlKey:true});
 rows.forEach(row => selection(row,true));
 await key(' '); selection(rows[2],false);
 assert.match(get('#status').textContent,/2 of 3 selected/);
 await key('Escape');
 rows.forEach((row,i) => { selection(row,false); assert.equal(rowAt(i),row); });
 assert.equal(get('#btnView').disabled,true);
});

test('Rename targets the selected entry, not a focused-but-unselected one (round-3 finding 7)', async () => {
 const rows=setup(3);
 update({session:{family:'test',canWrite:true}});
 rows[0].listeners.click({}); // select index 0, focus 0
 assert.equal(state.focus,0);
 assert.equal(selectedOne()?.path,'/item0');
 refreshToolbar();
 assert.equal(get('#btnRename').disabled,false,'Rename enabled for the single selected entry');
 // Ctrl+ArrowDown moves focus to row 1 WITHOUT changing the selection.
 await key('ArrowDown',{ctrlKey:true});
 assert.equal(state.focus,1);
 assert.equal(state.selection.has(0),true,'selection unchanged by Ctrl+Arrow');
 assert.equal(state.selection.has(1),false);
 assert.equal(selectedOne(),null,'no single selected+focused entry after Ctrl+Arrow');
 refreshToolbar();
 assert.equal(get('#btnRename').disabled,true,'Rename disabled: it must not target the focused-but-unselected row');
});

test('an empty folder offers New folder only where the table allows it (round 2, finding 2)', () => {
 setup(0);
 update({session:{family:'test',canWrite:true},dirClass:''});
 const normal = paintEmpty();
 assert.equal(normal.state,'folder-empty');
 assert.deepEqual(normal.action,{id:'btnMkdir',label:'New folder'});
 assert.equal(get('#listEmptyAction').hidden,false);
 // A protected folder is a guard denial: the offer is withdrawn rather than
 // forwarding to a button the server would answer 403 to.
 update({dirClass:'protected'});
 const guarded = paintEmpty();
 assert.equal(guarded.state,'folder-empty');
 assert.equal(guarded.action,null);
 assert.equal(get('#listEmptyAction').hidden,true);
 assert.equal(get('#listEmptyText').textContent,'This folder is empty.','the sentence is unchanged; only the offer goes');
 // 'warn' is not a denial — the server still decides there.
 update({dirClass:'warn'});
 assert.deepEqual(paintEmpty().action,{id:'btnMkdir',label:'New folder'});
 // Read-only withdraws it too, through the same table.
 update({dirClass:'',session:{family:'test',canWrite:false}});
 assert.equal(paintEmpty().action,null);
 update({session:{family:'test'},dirClass:''});
});

test('virtual scrolling and data renders rebuild rows with current selection and focus', async () => {
 const rows=setup(2501);
 assert.ok(rows.length<100);
 rows[0].listeners.click({});
 await key('a',{ctrlKey:true});
 assert.equal(rowAt(0),rows[0]);
 await key('End',{shiftKey:true});
 assert.equal(state.focus,2500);
 assert.equal(rowAt(0),undefined);
 selection(rowAt(2500),true);
 assert.equal(document.activeElement,rowAt(2500));
 await key(' '); selection(rowAt(2500),false);
 const last=rowAt(2500);
 render();
 assert.notEqual(rowAt(2500),last);
 selection(rowAt(2500),false);
 get('#listViewport').scrollTop=0;
 get('#listViewport').listeners.scroll();
 selection(rowAt(0),true);
 assert.equal(get('#list').tabIndex,0);
});
