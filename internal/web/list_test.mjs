// Run with: node --test internal/web/list_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {initList,render,selectedOne,refreshToolbar,paintEmpty,DEFAULT_PAGE,selectAllPlan,sizeCell,dateCell,selectionEntries} from './static/js/list.js';
import {state,update} from './static/js/state.js';
import {MAX_ROOTS,tooManySentence} from './static/js/why.js';

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
 querySelector() { return null; }
 querySelectorAll(selector) {
  assert.equal(selector,'[data-idx]');
  return this.children.filter(row => row.dataset.idx !== undefined);
 }
 contains(element) { return this.children.includes(element); }
 closest() { return null; }
 focus() { document.activeElement=this; this.listeners.focus?.(); }
 showModal() { this.open=true; }
 // A test sets `rect` on the element whose box it is reasoning about.
 getBoundingClientRect() { return this.rect || {left:0,top:0,right:0,bottom:0,width:0,height:0}; }
}
const elements=new Map();
const get=selector => {
 if (!elements.has(selector)) elements.set(selector,new Element());
 return elements.get(selector);
};
// The sheet records each rule's text, so a test can find the one list.js moves.
const sheet={href:'http://localhost/app.css',cssRules:[],insertRule(text) { this.cssRules.push({text,style:{}}); return this.cssRules.length-1; }};
globalThis.document={
 querySelector:get,
 createElement:() => new Element(),
 getElementById:id => get('#listRows').children.find(row => row.attrs.id===id),
 styleSheets:[sheet],addEventListener(){},activeElement:null,
 documentElement:{clientWidth:1024,clientHeight:768},
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

// setup paints a listing whose pages are cut at the module's own page size —
// no page is ever fetched here, so that is still DEFAULT_PAGE — exactly as a
// folder of `total` entries arrives. `make` names the entries; `path` is where
// the folder is (the /share rule hides volume roots only there).
function setup(total=3,{make=i => ({name:`item${i}`,path:`/item${i}`,type:i===0 ? 'dir' : 'file',size:0,mtime:0}),path='/share'}={}) {
 const entries=Array.from({length:total},(_,i) => make(i));
 const pages=new Map();
 for (let i=0;i<total;i+=DEFAULT_PAGE) pages.set(i/DEFAULT_PAGE,entries.slice(i,i+DEFAULT_PAGE));
 if (!total) pages.set(0,[]);
 update({session:{family:'test'},path,total,pages,selection:new Map(),focus:0,anchor:0,loading:false,filter:''});
 get('#searchBox').value='';
 get('#listViewport').scrollTop=0;
 document.activeElement=null;
 render();
 return get('#listRows').children.slice();
}
// typeFilter is a keystroke in the quick filter box, through the handler the
// app registered for it.
function typeFilter(text) {
 get('#searchBox').value=text;
 get('#searchBox').listeners.input({target:get('#searchBox')});
}
const selectedIndices=() => [...state.selection.keys()].sort((a,b) => a-b);
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

// The reads are what an administrator came for. Under /etc — which browse.go
// classes 'protected' lexically, along with /usr, /var and /root — View,
// Download, Properties and Search were all greyed out, because the display class
// was being fed into the reason table as a guard denial and the guard cause was
// applied to every action (Astra r1 #6).
test('a protected folder does not grey out the READ actions', () => {
 const rows=setup(3);
 update({session:{family:'test',canWrite:true},dirClass:'protected'});
 rows[1].listeners.click({}); // one plain file selected and focused
 refreshToolbar();
 for (const id of ['#btnDownload','#btnView','#btnProps']) {
  assert.equal(get(id).disabled,false,`${id} must stay usable inside a protected region`);
 }
 update({dirClass:''});
});

test('an empty folder offers New folder only where the table allows it (round 2, finding 2)', () => {
 setup(0);
 update({session:{family:'test',canWrite:true},dirClass:''});
 const normal = paintEmpty();
 assert.equal(normal.state,'folder-empty');
 assert.deepEqual(normal.action,{id:'btnMkdir',label:'New folder'});
 assert.equal(get('#listEmptyAction').hidden,false);
 // The display class is NOT a guard verdict (Astra r1 #6). browse.go's `class`
 // is lexical — "Display hints only", covering everything under /etc, /usr,
 // /var and /root — and reading it as a denial took New folder away from an
 // administrator standing in the directory they signed in to repair. The badge
 // and the path notice still say "protected"; the offer stands, and the server
 // refuses in its own words if it must.
 update({dirClass:'protected'});
 const guarded = paintEmpty();
 assert.equal(guarded.state,'folder-empty');
 assert.deepEqual(guarded.action,{id:'btnMkdir',label:'New folder'});
 assert.equal(get('#listEmptyAction').hidden,false);
 assert.equal(get('#listEmptyText').textContent,'This folder is empty.','the sentence is unchanged either way');
 // 'warn' is not a denial either — the server still decides there.
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
 // A folder this size never arrives in one response, so Ctrl+A refuses it and
 // leaves the selection alone (stabilization contract §3.3).
 await key('a',{ctrlKey:true});
 assert.deepEqual(selectedIndices(),[0]);
 assert.match(get('#status').textContent,/^This folder is too large to select all at once/);
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

// --- stabilization contract §3.3: Ctrl+A ---------------------------------------
//
// Ctrl+A used to switch on a select-all ("exclude") mode that no action could
// act on, so Ctrl+A followed by Delete said "Select items individually…". It now
// selects every VISIBLE row — when the listing came in one response and the
// count is within MAX_ROOTS — and otherwise says why and changes nothing.

const files=(dir,name=i => `item${i}`) => i => ({name:name(i),path:`${dir}/${name(i)}`,type:'file',size:0,mtime:0});

test('Ctrl+A in a folder of 3 selects all three', async () => {
 setup(3,{path:'/f'});
 rowAt(1).listeners.click({});
 await key('a',{ctrlKey:true});
 assert.deepEqual(selectedIndices(),[0,1,2]);
 for (const i of [0,1,2]) selection(rowAt(i),true);
 assert.match(get('#status').textContent,/3 of 3 selected/);
 assert.equal(state.focus,1,'focus stays where it was');
});

test('Ctrl+A in a folder of exactly 1,000 selects them all, and every action may carry them', async () => {
 setup(MAX_ROOTS,{make:files('/f'),path:'/f'});
 update({session:{family:'test',canWrite:true}});
 rowAt(0).listeners.click({});
 await key('a',{ctrlKey:true});
 assert.equal(state.selection.size,1000);
 assert.ok(get('#status').textContent.startsWith(`${(1000).toLocaleString()} of ${(1000).toLocaleString()} selected`));
 refreshToolbar();
 for (const id of ['#btnDelete','#btnCopy','#btnMove','#btnPerms','#btnDownload']) assert.equal(get(id).disabled,false,id);
 const entries=await selectionEntries();
 assert.equal(entries.length,1000);
 assert.equal(entries[999].path,'/f/item999');
});

test('Ctrl+A in a folder of 1,001 selects nothing and says why, with the number', async () => {
 setup(MAX_ROOTS+1,{make:files('/f'),path:'/f'});
 rowAt(5).listeners.click({});
 get('#announce').textContent='';
 await key('a',{ctrlKey:true});
 assert.deepEqual(selectedIndices(),[5],'the selection is left exactly as it was');
 const sentence=`This folder has ${(1001).toLocaleString()} items; select-all works on up to ${(1000).toLocaleString()} at a time. Filter the names or select a range.`;
 assert.equal(get('#status').textContent,sentence);
 assert.equal(get('#announce').textContent,sentence,'and a screen reader hears it');
});

test('Ctrl+A in a folder of 1,500 with a filter matching 30 selects exactly those 30', async () => {
 setup(1500,{make:files('/f',i => i%50 === 0 ? `photo${i}.jpg` : `doc${i}.txt`),path:'/f'});
 await key('a',{ctrlKey:true});
 assert.equal(state.selection.size,0,'1,500 is past the bound');
 assert.match(get('#status').textContent,new RegExp(`^This folder has ${(1500).toLocaleString()} items;`));
 typeFilter('.jpg');
 await key('a',{ctrlKey:true});
 assert.equal(state.selection.size,30);
 assert.ok([...state.selection.values()].every(e => e.name.endsWith('.jpg')),'every selected row is one the filter shows');
 assert.match(get('#status').textContent,new RegExp(`^30 of ${(1500).toLocaleString()} selected`));
 // A filter that still matches too many says so in its own words.
 typeFilter('doc');
 await key('Escape');
 await key('a',{ctrlKey:true});
 assert.equal(state.selection.size,0);
 assert.equal(get('#status').textContent,
  `${(1470).toLocaleString()} items match the filter; select-all works on up to ${(1000).toLocaleString()} at a time. Narrow the filter or select a range.`);
});

test('Ctrl+A at /share skips the volume rows the listing hides', async () => {
 const names=['Public','CACHEDEV1_DATA','Multimedia','CACHEDEV2_DATA','homes'];
 const make=i => ({name:names[i],path:`/share/${names[i]}`,type:'dir',volumeRoot:names[i].startsWith('CACHEDEV'),size:0,mtime:0});
 setup(5,{make,path:'/share'});
 await key('a',{ctrlKey:true});
 assert.deepEqual([...state.selection.values()].map(e => e.name),['Public','Multimedia','homes']);
 // The rule is /share's alone: the same flags anywhere else hide nothing.
 setup(5,{make,path:'/share/CACHEDEV1_DATA'});
 await key('a',{ctrlKey:true});
 assert.equal(state.selection.size,5);
});

test('Ctrl+A over a listing read in more than one response refuses, naming what is loaded', async () => {
 setup(2501,{make:files('/big'),path:'/big'});
 const first=state.pages.get(0);
 update({pages:new Map([[0,first]])});
 await key('a',{ctrlKey:true});
 assert.equal(get('#status').textContent,`This folder is too large to select all at once (only its first ${(2000).toLocaleString()} entries are loaded).`);
 assert.equal(state.selection.size,0);
});

test('selectAllPlan: one response and the bound, or one sentence and nothing selected', () => {
 const page=n => Array.from({length:n},(_,i) => ({name:`n${i}`}));
 assert.equal(selectAllPlan({pages:new Map([[0,page(3)]]),total:3}).selection.size,3);
 assert.equal(selectAllPlan({pages:new Map([[0,[]]]),total:0}).selection.size,0,'an empty folder selects nothing, quietly');
 assert.equal(selectAllPlan({pages:new Map(),loading:true}).sentence,'This folder is still loading, so nothing was selected.');
 assert.equal(selectAllPlan({pages:new Map(),total:0}).sentence,'Nothing is listed here, so nothing was selected.');
 assert.equal(selectAllPlan({pages:new Map([[0,page(2000)],[3,page(2000)]]),total:9000}).sentence,
  `This folder is too large to select all at once (only ${(4000).toLocaleString()} of its ${(9000).toLocaleString()} entries are loaded).`);
 assert.equal(selectAllPlan({pages:new Map([[0,page(500)],[1,page(500)]]),total:1000}).sentence,
  `This folder is too large to select all at once (its ${(1000).toLocaleString()} entries were listed in more than one response).`);
 assert.equal(selectAllPlan({pages:new Map([[0,page(1001)]]),total:1001}).selection,undefined);
});

// --- §3.4: ranges and filters --------------------------------------------------

test('a Shift range adds only the visible rows between anchor and target', async () => {
 setup(11,{make:files('/f',i => i%2 ? `odd${i}` : `even${i}`),path:'/f'});
 typeFilter('even');
 rowAt(2).listeners.click({});
 rowAt(8).listeners.click({shiftKey:true});
 assert.deepEqual(selectedIndices(),[2,4,6,8],'the odd rows between were hidden, so they are not selected');
 for (const i of [3,5,7]) selection(rowAt(i),false);
 // The keyboard's ranges obey the same rule.
 await key('Escape');
 rowAt(0).listeners.click({});
 await key('End',{shiftKey:true});
 assert.deepEqual(selectedIndices(),[0,2,4,6,8,10]);
 assert.ok([...state.selection.values()].every(e => e.name.startsWith('even')));
});

test('a filter change takes newly hidden rows out of the selection, and says so', async () => {
 const names=['alpha','beta','gamma','alps','delta','alto'];
 setup(6,{make:files('/f',i => names[i]),path:'/f'});
 rowAt(0).listeners.click({});
 rowAt(1).listeners.click({ctrlKey:true});
 rowAt(3).listeners.click({ctrlKey:true});
 assert.deepEqual(selectedIndices(),[0,1,3]);
 get('#announce').textContent='';
 typeFilter('al');
 assert.deepEqual(selectedIndices(),[0,3],'beta is hidden, so it is no longer selected');
 assert.equal(get('#announce').textContent,'1 selected item is hidden by the filter and no longer selected.');
 assert.match(get('#status').textContent,/^2 of 6 selected/);
 // Clearing the filter shows beta again; it does not come back selected.
 typeFilter('');
 assert.deepEqual(selectedIndices(),[0,3]);
 typeFilter('zzz');
 assert.equal(get('#announce').textContent,'2 selected items are hidden by the filter and no longer selected.');
 // With nothing selected there is nothing to say.
 typeFilter('');
 get('#announce').textContent='';
 typeFilter('beta');
 assert.equal(get('#announce').textContent,'');
});

test('an action receives the entries the rows SHOWED, not what the indices say later (§3.1)', async () => {
 setup(4,{make:files('/f'),path:'/f'});
 rowAt(1).listeners.click({});
 rowAt(2).listeners.click({ctrlKey:true});
 // The listing is read again underneath the selection, and the folder changed.
 update({pages:new Map([[0,Array.from({length:4},files('/f',i => `renamed${i}`))]])});
 assert.deepEqual((await selectionEntries()).map(e => e.path),['/f/item1','/f/item2']);
});

// --- §3.5: past MAX_ROOTS ------------------------------------------------------

test('past MAX_ROOTS every multi-item control refuses in the table’s sentence — Download included', async () => {
 setup(1500,{make:files('/f'),path:'/f'});
 update({session:{family:'test',canWrite:true}});
 rowAt(0).listeners.click({});
 rowAt(1000).listeners.click({shiftKey:true});
 assert.equal(state.selection.size,1001);
 refreshToolbar();
 const sentence=tooManySentence(1001);
 for (const id of ['#btnDelete','#btnCopy','#btnMove','#btnPerms','#btnDownload','#btnDownloadAs']) {
  assert.equal(get(id).disabled,true,id);
  assert.equal(get(id).title,sentence,`${id} says why, not what it would have done`);
 }
 // The keyboard is no way round it: Delete, Ctrl+C and F9 resolve through here.
 await assert.rejects(selectionEntries(),err => err.message===sentence);
 // One fewer, and they come back.
 rowAt(1000).listeners.click({ctrlKey:true});
 refreshToolbar();
 assert.equal(get('#btnDelete').disabled,false);
 assert.equal(get('#btnDownload').title,'Download the selection as a ZIP archive');
});

// --- §3.6: the cells -----------------------------------------------------------

test('Size and Modified read like a file manager, with the exact value as the title', () => {
 const mtime='2026-09-13T10:05:00Z';
 const items=[
  {name:'docs',path:'/f/docs',type:'dir',size:4096,mtime},
  {name:'a.bin',path:'/f/a.bin',type:'file',size:1536,mtime},
  {name:'big.iso',path:'/f/big.iso',type:'file',size:5*1024**3,mtime},
 ];
 setup(3,{make:i => items[i],path:'/f'});
 const cells=i => rowAt(i).children;
 assert.equal(cells(0)[1].textContent,'—','a folder’s size is not the inode’s 4,096');
 assert.equal(cells(0)[1].attrs.title,undefined);
 assert.equal(cells(1)[1].textContent,'1.5 KiB');
 assert.equal(cells(1)[1].attrs.title,`${(1536).toLocaleString()} bytes`);
 assert.equal(cells(2)[1].textContent,'5 GiB');
 assert.equal(cells(2)[1].attrs.title,`${(5*1024**3).toLocaleString()} bytes`);
 const date=new Date(mtime);
 assert.equal(cells(1)[3].textContent,date.toLocaleString(undefined,{dateStyle:'short',timeStyle:'short'}));
 assert.equal(cells(1)[3].attrs.title,date.toLocaleString());
 assert.notEqual(cells(1)[3].textContent,cells(1)[3].attrs.title,'the cell is the short form, the title the full one');
 assert.equal(cells(1)[2].textContent,'file','no other column changes');
});

test('sizeCell and dateCell say "—" for what they cannot honestly show', () => {
 assert.deepEqual(sizeCell({type:'file',size:0}),{text:'0 B',title:'0 bytes'});
 assert.deepEqual(sizeCell({type:'file'}),{text:'—',title:''});
 assert.deepEqual(sizeCell({type:'file',size:-1}),{text:'—',title:''});
 // A link to a folder is a folder here, as everywhere in the listing.
 assert.deepEqual(sizeCell({type:'symlink',isSymlink:true,targetType:'dir',linkResolved:'/x',size:9}),{text:'—',title:''});
 assert.deepEqual(dateCell(undefined),{text:'—',title:''});
 assert.deepEqual(dateCell('not a date'),{text:'—',title:''});
 assert.equal(dateCell(0).title,new Date(0).toLocaleString());
});

// Astra r1 P2: render() formats every loaded row on each scroll and filter
// keystroke, and Date#toLocaleString with options builds a formatter per call —
// about 170 ms per repaint of 2,000 rows. dateCell makes its two formatters once
// and reuses them, and still says exactly what toLocaleString says.
test('dateCell makes its two formatters once, and its text and title are toLocaleString’s', async () => {
 const stamps=Array.from({length:2000},(_,i) => new Date(Date.UTC(2026,0,1)+i*7*3600000).toISOString());
 stamps.push('1970-01-01T00:00:00Z','2026-03-29T00:59:59Z','2026-10-25T01:00:00Z','2038-01-19T03:14:07Z');
 // What the cells said before §3.6's formatting was cached, computed first.
 const want=stamps.map(s => { const d=new Date(s); return {text:d.toLocaleString(undefined,{dateStyle:'short',timeStyle:'short'}),title:d.toLocaleString()}; });
 const Real=Intl.DateTimeFormat,realToLocale=Date.prototype.toLocaleString;
 let built=0,perCall=0;
 Intl.DateTimeFormat=function DateTimeFormat(...args) { built++; return new Real(...args); };
 Date.prototype.toLocaleString=function(...args) { perCall++; return realToLocale.apply(this,args); };
 try {
  // A module instance of its own, so the first formatter is made under the spy.
  const {dateCell:fresh}=await import('./static/js/list.js?dateformats');
  const got=stamps.map(fresh);
  assert.equal(built,2,'one formatter for the short text and one for the title, for every row there is');
  assert.equal(perCall,0,'never the per-call path');
  for (let i=0;i<stamps.length;i++) assert.deepEqual(got[i],want[i],stamps[i]);
  // The instance the page renders with reuses its own as well.
  built=0;
  for (const s of stamps) dateCell(s);
  assert.ok(built<=2,`render's dateCell built ${built} formatters for ${stamps.length} rows`);
  assert.equal(perCall,0);
 } finally {
  Intl.DateTimeFormat=Real;
  Date.prototype.toLocaleString=realToLocale;
 }
});

// --- §3.7: the context menu opens where it was asked for ------------------------

const menuRule=() => sheet.cssRules.find(rule => String(rule.text).startsWith('#ctxMenu'));
const placed=() => [menuRule().style.left,menuRule().style.top];

test('a right-click opens the menu at the pointer, through a CSSOM rule and no style attribute', () => {
 setup(3,{path:'/f'});
 const menu=get('#ctxMenu');
 menu.rect={left:0,top:0,right:180,bottom:240,width:180,height:240};
 assert.equal(menuRule().text,'#ctxMenu { left: 0px; top: 0px; right: auto; bottom: auto; }',
  'the stylesheet’s corner placement is overridden, not fought');
 rowAt(1).rect={left:0,top:72,right:1000,bottom:108,width:1000,height:36};
 rowAt(1).listeners.contextmenu({preventDefault(){},clientX:300,clientY:90});
 assert.equal(menu.hidden,false);
 assert.deepEqual(placed(),['300px','90px']);
 assert.equal(menu.attrs.style,undefined,'never an inline style');
 // In the bottom-right corner it flips up and to the left, inside the viewport.
 rowAt(2).rect={left:0,top:740,right:1024,bottom:768,width:1024,height:28};
 rowAt(2).listeners.contextmenu({preventDefault(){},clientX:1000,clientY:750});
 assert.deepEqual(placed(),['820px','510px']);
 menu.hidden=true;
});

test('the pointer is judged against the row as it was clicked, before the selection moves anything', () => {
 // Found live: selecting relabels Download, a narrow toolbar rewraps, and every
 // row moves 36 px. Measured after the selection changed, the pointer was
 // "outside" its own row and the menu opened at the row's edge instead.
 setup(3,{path:'/f'});
 const menu=get('#ctxMenu');
 menu.rect={left:0,top:0,right:180,bottom:240,width:180,height:240};
 const row=rowAt(1);
 row.rect={left:0,top:317,right:469,bottom:353,width:469,height:36};
 const shift=get('#btnDownload');
 const label=Object.getOwnPropertyDescriptor(shift,'textContent');
 // The toolbar repaint moves the row up, as the rewrap did.
 Object.defineProperty(shift,'textContent',{configurable:true,get() { return this._text; },set(value) { this._text=value; row.rect={...row.rect,top:281,bottom:317}; }});
 try {
  row.listeners.contextmenu({preventDefault(){},clientX:200,clientY:335});
  assert.deepEqual(placed(),['200px','335px'],'opened at the pointer, not at the row’s edge');
 } finally {
  if (label) Object.defineProperty(shift,'textContent',label); else delete shift.textContent;
  menu.hidden=true;
 }
});

test('Shift+F10 and the Menu key open it just below the focused row, at its left edge', async () => {
 setup(3,{path:'/f'});
 const menu=get('#ctxMenu');
 menu.rect={left:0,top:0,right:180,bottom:240,width:180,height:240};
 rowAt(1).listeners.click({});
 rowAt(1).rect={left:16,top:72,right:1000,bottom:108,width:984,height:36};
 await key('F10',{shiftKey:true});
 assert.equal(menu.hidden,false);
 assert.deepEqual(placed(),['16px','108px']);
 menu.hidden=true;
 // Near the bottom it opens ABOVE the row, not over it.
 rowAt(1).rect={left:16,top:700,right:1000,bottom:736,width:984,height:36};
 await key('ContextMenu');
 assert.deepEqual(placed(),['16px','460px']);
 // A contextmenu event the keyboard raised carries no pointer (0,0, outside the
 // row): the menu opens at the row, as the key itself would have opened it.
 rowAt(1).rect={left:16,top:72,right:1000,bottom:108,width:984,height:36};
 rowAt(1).listeners.contextmenu({preventDefault(){},clientX:0,clientY:0});
 assert.deepEqual(placed(),['16px','108px']);
 menu.hidden=true;
});
