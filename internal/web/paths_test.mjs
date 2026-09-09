// Run with: node --test internal/web/paths_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {pathArgs,route,parseRoute,rawPath,bytePath} from './static/js/dom.js';
import {fileTarget,isDirectory,isReadable} from './static/js/badges.js';
import {contextMenu,open} from './static/js/list.js';
import {download,view,properties} from './static/js/viewer.js';

test('hash routes preserve authoritative bytes and accept text and legacy bookmarks', () => {
 const raw='/share/\xff/\xfe #?.txt', entry=bytePath(raw);
 assert.equal(route(entry),'#b64/'+entry.pathB64);
 assert.deepEqual(pathArgs(parseRoute(route(entry))),{pathB64:entry.pathB64});
 assert.equal(rawPath(parseRoute(route(entry))),raw);
 assert.equal(rawPath(parseRoute('#/display?pathB64='+entry.pathB64)),raw);
 const text={path:'/share/æ #?.txt'};
 assert.deepEqual(parseRoute(route(text)),{...text,pathB64:''});
 assert.deepEqual(parseRoute(''),{path:'/share',pathB64:''});
 for (const hash of ['#b64/','#b64/%%','#b64/'+bytePath('relative').pathB64]) assert.throws(() => parseRoute(hash));
 // Parent navigation and breadcrumbs slice raw bytes, including invalid UTF-8.
 const parent=bytePath(rawPath(entry).slice(0,rawPath(entry).lastIndexOf('/')));
 assert.equal(rawPath(parseRoute(route(parent))),'/share/\xff');
});

class Element {
 constructor() { this.children=[]; this.listeners={}; this.attrs={}; this.classList={remove(){}}; }
 setAttribute(key,value) { this.attrs[key]=value; }
 append(...children) { this.children.push(...children); }
 replaceChildren(...children) { this.children=children; }
 addEventListener(event,fn) { this.listeners[event]=fn; }
 querySelector() { return this.children.find(child => !child.disabled); }
 click() { this.listeners.click?.(); }
 remove() {}
 focus() {}
 showModal() { this.open=true; }
}
const elements=new Map();
globalThis.document={
 querySelector(selector) { if (!elements.has(selector)) elements.set(selector,new Element()); return elements.get(selector); },
 createElement() { return new Element(); },
 body:new Element(),
};
globalThis.location={hash:''};
const requests=[];
globalThis.fetch=async url => {
 requests.push(new URL(url,'http://localhost/'));
 return {ok:true,status:200,json:async () => ({content:'ok',bytes:2,mode:'0644'})};
};

test('non-UTF-8 directory list navigation keeps pathB64', () => {
 const entry={...bytePath('/share/\xff'),name:'�',nameB64:'_w',type:'dir'};
 open(entry);
 assert.equal(location.hash,'#b64/'+entry.pathB64);
 assert.deepEqual(pathArgs(parseRoute(location.hash)),{pathB64:entry.pathB64});
});

test('symlink target navigation and file actions prefer resolved bytes over display and alias paths', async () => {
 const target=bytePath('/share/\xff.txt');
 const link={name:'link',path:'/share/link',pathB64:bytePath('/share/alias\xfe').pathB64,type:'symlink',linkResolved:target.path,linkResolvedB64:target.pathB64,targetType:'dir'};
 assert.ok(isDirectory(link));
 contextMenu(link);
 document.querySelector('#ctxMenu').children.find(button => button.textContent==='Go to target').click();
 assert.equal(location.hash,'#b64/'+target.pathB64);
 link.targetType='file';
 assert.ok(isReadable(link));
 assert.deepEqual(pathArgs(fileTarget(link)),{pathB64:target.pathB64});
 await view(link);
 assert.equal(requests.at(-1).pathname,'/api/fs/text');
 assert.equal(requests.at(-1).searchParams.get('pathB64'),target.pathB64);
 assert.equal(requests.at(-1).searchParams.has('path'),false);
 download(link);
 const url=new URL(document.body.children.at(-1).attrs.href,'http://localhost/');
 assert.equal(url.pathname,'/api/fs/download');
 assert.equal(url.searchParams.get('pathB64'),target.pathB64);
 assert.equal(url.searchParams.has('path'),false);
 await properties(link);
 assert.equal(requests.at(-1).searchParams.get('pathB64'),link.pathB64);
 assert.deepEqual(pathArgs(fileTarget({...link,linkResolvedB64:undefined})),{path:target.path});
});

test('ordinary file actions retain their own non-UTF-8 path', async () => {
 const entry={...bytePath('/share/\xff'),name:'�',nameB64:'_w',type:'file'};
 await view(entry);
 assert.equal(requests.at(-1).searchParams.get('pathB64'),entry.pathB64);
});
