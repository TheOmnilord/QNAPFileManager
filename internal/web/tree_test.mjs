// Run with: node --test internal/web/tree_test.mjs
//
// Stabilization contract §4.2: expanding a folder in the tree reads ONE page,
// folders first, and says so when that page cannot have held every folder.
// Before the patch node().expand looped over every page of the folder, so a
// folder of 200,000 files cost 400 requests to show its handful of subfolders.
import assert from 'node:assert/strict';
import {test} from 'node:test';

// An element double just deep enough for tree.js: attributes, children with
// parents (isConnected is whether the chain reaches the container), and the
// selectors the tree itself asks.
class Element {
 constructor(tag) {
  this.tagName = String(tag).toUpperCase(); this.attrs = {}; this.children = []; this.parentElement = null;
  this.listeners = {}; this.textContent = ''; this.hidden = false; this.disabled = false; this.tabIndex = -1; this.root = false;
 }
 setAttribute(key, value) { this.attrs[key] = String(value); if (key === 'id') this.id = String(value); }
 getAttribute(key) { return this.attrs[key] ?? null; }
 append(...kids) { for (const kid of kids) { kid.parentElement = this; this.children.push(kid); } }
 replaceChildren(...kids) { for (const kid of this.children) kid.parentElement = null; this.children = []; this.append(...kids); }
 get lastElementChild() { return this.children.at(-1) ?? null; }
 get isConnected() { for (let node = this; node; node = node.parentElement) if (node.root) return true; return false; }
 get role() { return this.attrs.role; }
 addEventListener(type, fn) { this.listeners[type] = fn; }
 descendants() { return this.children.flatMap(kid => [kid, ...kid.descendants()]); }
 querySelectorAll(selector) {
  if (selector === '[role=treeitem]') return this.descendants().filter(node => node.role === 'treeitem');
  if (selector === ':scope > [role=group] > [role=treeitem]') return this.children.filter(node => node.role === 'group').flatMap(group => group.children.filter(node => node.role === 'treeitem'));
  if (selector === '[role=group] > [role=treeitem]') return this.descendants().filter(node => node.role === 'treeitem' && node.parentElement?.role === 'group');
  throw new Error(`the tree double does not know ${selector}`);
 }
 querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
 closest(selector) {
  if (selector === '[hidden]') { for (let node = this; node; node = node.parentElement) if (node.hidden) return node; return null; }
  if (selector === '[role=treeitem]') { for (let node = this; node; node = node.parentElement) if (node.role === 'treeitem') return node; return null; }
  throw new Error(`the tree double does not know closest(${selector})`);
 }
 focus() { document.activeElement = this; }
}
// Anything tree.js reports goes to a sink rather than throwing on a null.
const sinks = new Map();
globalThis.document = {
 createElement: tag => new Element(tag),
 querySelector: selector => { if (!sinks.has(selector)) sinks.set(selector, new Element('div')); return sinks.get(selector); },
 activeElement: null,
};

// The server: one listing per path, and every request it was asked.
const listings = new Map(), requests = [];
globalThis.fetch = async url => {
 const asked = new URL(url, 'http://localhost/');
 requests.push(asked);
 const listing = listings.get(asked.searchParams.get('path'));
 const status = listing ? 200 : 404;
 return new Response(JSON.stringify(listing ?? {error: {message: 'not found'}}), {status, headers: {'Content-Type': 'application/json'}});
};

const {renderTree, treeContinues, TREE_PAGE, TREE_MORE} = await import('./static/js/tree.js');
const {update} = await import('./static/js/state.js');
update({session: {user: 'alice', csrf: 'token'}});

const at = (parent, name) => `${parent === '/' ? '' : parent}/${name}`;
const dir = (parent, name) => ({name, path: at(parent, name), type: 'dir'});
const file = (parent, name) => ({name, path: at(parent, name), type: 'file'});
const folders = (parent, n) => Array.from({length: n}, (_, i) => dir(parent, `d${String(i).padStart(4, '0')}`));
const serve = (path, entries, total = entries.length, limit = TREE_PAGE) => listings.set(path, {path, entries, total, limit});
const fresh = () => { listings.clear(); requests.length = 0; const box = new Element('nav'); box.root = true; return box; };
const childrenOf = item => item.children.find(node => node.role === 'group')?.children ?? [];
const key = (item, name) => item.listeners.keydown({target: item, key: name, preventDefault() {}, stopPropagation() {}});

test('the continuation line is the contract’s sentence, verbatim', () => {
 assert.equal(TREE_MORE, 'More entries are not shown — open this folder.');
 assert.equal(TREE_PAGE, 500);
});

test('expanding a folder reads one page, folders first', async () => {
 const box = fresh();
 serve('/', [dir('/', 'etc'), dir('/', 'share'), file('/', 'notes.txt')]);
 const deepest = await renderTree({container: box, onPick() {}});
 assert.equal(requests.length, 1, 'one request, not one per page');
 const asked = requests[0];
 assert.equal(asked.pathname, '/api/fs/list');
 assert.equal(asked.searchParams.get('path'), '/');
 assert.equal(asked.searchParams.get('limit'), '500');
 assert.equal(asked.searchParams.get('dirsFirst'), 'true', 'folders before files, so one page holds them');
 assert.equal(asked.searchParams.get('sort'), 'name');
 assert.equal(asked.searchParams.get('offset'), null, 'the first page, never a later one');
 const root = box.children[0];
 assert.equal(deepest, root);
 assert.deepEqual(childrenOf(root).map(node => node.entry?.name), ['etc', 'share'], 'the folders, and not the file');
 assert.equal(root.getAttribute('aria-describedby'), null, 'nothing more to say');
});

test('a full page of folders short of the total ends with the continuation line', async () => {
 const box = fresh();
 serve('/', folders('/', TREE_PAGE), 12000);
 await renderTree({container: box, onPick() {}});
 assert.equal(requests.length, 1, 'still one request, however large the folder');
 const root = box.children[0], kids = childrenOf(root);
 assert.equal(kids.length, TREE_PAGE + 1);
 const more = kids.at(-1);
 assert.equal(more.textContent, TREE_MORE);
 assert.equal(more.tagName, 'DIV');
 assert.equal(more.role, undefined, 'not a treeitem');
 assert.equal(more.attrs.class, 'treeMore');
 assert.equal(box.querySelectorAll('[role=treeitem]').length, TREE_PAGE + 1, 'the root and its 500 folders, and not the line');
 assert.equal(root.getAttribute('aria-describedby'), more.id, 'the folder is described by the line a screen reader never lands on');
 assert.ok(more.id, 'the line has an id to be described by');
});

test('the arrow keys pass the continuation line by', async () => {
 const box = fresh();
 serve('/', folders('/', TREE_PAGE), 501);
 await renderTree({container: box, onPick() {}});
 const items = box.querySelectorAll('[role=treeitem]'), root = items[0], last = items.at(-1);
 key(last, 'ArrowDown');
 assert.equal(document.activeElement, last, 'Down from the last folder stays on it');
 key(root, 'End');
 assert.equal(document.activeElement, last, 'End is the last folder, not the line after it');
 // Collapsing the folder hides the line with its children.
 await root.expand();
 assert.equal(root.lastElementChild.hidden, true);
 assert.equal(childrenOf(root).at(-1).closest('[hidden]'), root.lastElementChild);
});

test('a full page with any file in it already holds every folder', async () => {
 const box = fresh();
 serve('/', [...folders('/', TREE_PAGE - 1), file('/', 'zz.log')], 200000);
 await renderTree({container: box, onPick() {}});
 const kids = childrenOf(box.children[0]);
 assert.equal(kids.length, TREE_PAGE - 1);
 assert.ok(kids.every(node => node.role === 'treeitem'), 'no continuation line');
 assert.equal(requests.length, 1);
});

test('a page the server sized smaller is still a full page', async () => {
 const box = fresh();
 serve('/', folders('/', 200), 300, 200);
 await renderTree({container: box, onPick() {}});
 assert.equal(childrenOf(box.children[0]).at(-1).textContent, TREE_MORE);
});

test('revealing a path stops at the first folder the page did not hold', async () => {
 // The ancestor reveal is unchanged (§4.2): a missing link ends the descent, as
 // a hidden folder always has. /share/Zeta sorts past the first page here.
 const box = fresh();
 serve('/', [dir('/', 'share')]);
 serve('/share', folders('/share', TREE_PAGE), 900);
 const deepest = await renderTree({container: box, onPick() {}, expandTo: '/share/Zeta/inner'});
 assert.equal(deepest?.entry?.path, '/share');
 assert.deepEqual(requests.map(asked => asked.searchParams.get('path')), ['/', '/share'], 'nothing asked of a folder the tree never showed');
 assert.equal(childrenOf(deepest).at(-1).textContent, TREE_MORE, 'and the folder says there is more');
});

test('treeContinues: only a full page of folders that is not the whole folder', () => {
 const dirs = n => Array.from({length: n}, (_, i) => ({name: `d${i}`, type: 'dir'}));
 const link = {name: 'l', type: 'symlink', isSymlink: true, targetType: 'dir', linkResolved: '/x'};
 const cases = [
  ['full, all folders, more beyond', {entries: dirs(500), total: 501, limit: 500}, true],
  ['full, all folders, and that is all of them', {entries: dirs(500), total: 500, limit: 500}, false],
  ['not full', {entries: dirs(499), total: 9999, limit: 500}, false],
  ['a file on the page', {entries: [...dirs(499), {name: 'f', type: 'file'}], total: 9999, limit: 500}, false],
  ['a symlink to a folder sorts among the files', {entries: [...dirs(499), link], total: 9999, limit: 500}, false],
  ['the server’s smaller page size', {entries: dirs(200), total: 300, limit: 200}, true],
  ['no limit in the answer: the size asked for', {entries: dirs(500), total: 600}, true],
  ['no limit, and short of the size asked for', {entries: dirs(200), total: 600}, false],
  ['empty', {entries: [], total: 0, limit: 500}, false],
  ['no total', {entries: dirs(500), limit: 500}, false],
  ['no page at all', undefined, false],
 ];
 for (const [name, page, want] of cases) assert.equal(treeContinues(page), want, name);
});
