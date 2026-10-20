// Run with: node --test internal/web/search_session_test.mjs
//
// Astra r5 on the QKVM fix, and the hidden-items default after it: "Include
// mounted sub-folders" (and since then "Include hidden items") is ticked in the
// markup, and the search teardown cleared it to false on every session change —
// including the one connect() makes on every page load, update({listener})
// while the session is still null, which sessionTransition reads as a sign-out.
// So the box opened UNTICKED on QTS and hero alike, and a default search of
// /share excluded every volume. The markup-only test could not see that; this
// runs the real sequence against the real modules, with nothing but a stub DOM.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';

class Node {
 constructor() {
  this.attrs = {}; this.children = []; this.textContent = ''; this.value = ''; this.hidden = false;
  this.disabled = false; this.checked = false; this.open = false; this.title = ''; this.classes = new Set();
  this.classList = {toggle: (n, on) => on ? this.classes.add(n) : this.classes.delete(n), add: n => this.classes.add(n), remove: n => this.classes.delete(n), contains: n => this.classes.has(n)};
 }
 setAttribute(k, v) { this.attrs[k] = String(v); }
 getAttribute(k) { return this.attrs[k] ?? null; }
 removeAttribute(k) { delete this.attrs[k]; }
 append(...kids) { this.children.push(...kids); }
 replaceChildren(...kids) { this.children = kids; }
 addEventListener() {}
 querySelector() { return null; }
 querySelectorAll() { return []; }
 focus() {}
 select() {}
 showModal() { this.open = true; }
 close() { this.open = false; }
}
const nodes = new Map();
const $ = sel => { if (!nodes.has(sel)) nodes.set(sel, new Node()); return nodes.get(sel); };
globalThis.document = {querySelector: $, createElement: () => new Node(), addEventListener() {}, activeElement: null, hidden: false, getElementById: () => null, styleSheets: []};
globalThis.window = {addEventListener() {}};
globalThis.matchMedia = () => ({matches: false});
globalThis.location = {hash: ''};

const {state, update} = await import('./static/js/state.js');
const {initSearch, openSearch, showResults, closeResults, SEARCH_CROSS_DEFAULT, SEARCH_HIDDEN_DEFAULT} = await import('./static/js/search.js');

// The page as index.html builds it: the crossing row visible, both boxes
// ticked, "match pattern" not.
$('#searchCrossRow').hidden = false;
$('#searchCross').checked = true;
$('#searchHidden').checked = true;
$('#searchGlob').checked = false;
initSearch();

const alice = family => ({user: 'alice', uid: 1000, gid: 100, family, authenticated: true, canWrite: true});
const bob = family => ({user: 'bob', uid: 1001, gid: 100, family, authenticated: true, canWrite: true});
const reopen = () => { $('#dlgSearch').close(); openSearch(); };

// The two boxes that start every session ticked (owner, 2026-09-23), each with
// the constant the teardown restores and the markup that must agree with it.
const BOXES = [
 {id: '#searchCross', label: 'Include mounted sub-folders', constant: SEARCH_CROSS_DEFAULT},
 {id: '#searchHidden', label: 'Include hidden items', constant: SEARCH_HIDDEN_DEFAULT},
];

test('each default is the markup’s own, and both are ticked; match pattern is not', () => {
 const html = readFileSync(new URL('./static/index.html', import.meta.url), 'utf8');
 for (const box of BOXES) {
  assert.equal(new RegExp(`<input type="checkbox" id="${box.id.slice(1)}" checked>`).test(html), box.constant, box.label);
  assert.equal(box.constant, true, box.label);
 }
 assert.match(html, /<input type="checkbox" id="searchGlob">/);
});

for (const family of ['qts', 'quts_hero']) {
 for (const box of BOXES) {
  test(`${family}: “${box.label}” is ticked on first load, kept through the session, and ticked again for the next one`, () => {
   // connect(): the door first, with no session yet — the transient that used
   // to clear the boxes — then the session itself.
   update({session: null});
   update({listener: 'qts'});
   update({session: alice(family)});
   reopen();
   assert.equal($('#searchCrossRow').hidden, false, 'the crossing box is offered');
   assert.equal($(box.id).checked, true, 'first open after a page load must be ticked');
   assert.equal($('#searchGlob').checked, false, 'match pattern stays off');

   // A deliberate untick is the user's, for this session: kept on reopen, and
   // kept through a same-user refresh (the minute poll, a read-only toggle).
   $(box.id).checked = false;
   reopen();
   assert.equal($(box.id).checked, false);
   update({session: {...alice(family), canWrite: false}});
   reopen();
   assert.equal($(box.id).checked, false, 'a refresh is not a new session');

   // Sign-out and sign-in: back to the default, not to off.
   update({session: null});
   assert.equal(state.session, null);
   update({session: alice(family)});
   reopen();
   assert.equal($(box.id).checked, true, 'a fresh session starts at the default');

   // A switch of user is a fresh session too.
   $(box.id).checked = false;
   $('#searchGlob').checked = true;
   update({session: bob(family)});
   reopen();
   assert.equal($(box.id).checked, true, 'the next user does not inherit the untick');
   assert.equal($('#searchGlob').checked, false, 'nor the previous user’s pattern switch');
   $('#dlgSearch').close();
  });
 }
}

// Stabilization contract §3.1: a selection never holds a row the user cannot
// see. The listing's selection is put away while the results cover it, and the
// quick filter can be typed into meanwhile; what comes back is only what that
// filter still shows. And a listing reloaded underneath gets nothing back at
// all, because its indices now name other files.
test('a selection put away by the results comes back only as far as the filter now shows it', () => {
 const alpha = {name: 'alpha', path: '/f/alpha'}, beta = {name: 'beta', path: '/f/beta'};
 const results = {query: 'a', root: '/f', detail: '', hits: [], focus: -1, open: false};
 update({session: alice('qts')});
 update({path: '/f', filter: '', selection: new Map([[0, alpha], [1, beta]]), focus: 1, anchor: 0, searchResults: results});
 showResults();
 assert.equal(state.selection.size, 0, 'under the results the listing’s selection counts for nothing');
 update({filter: 'al'});
 closeResults();
 assert.deepEqual([...state.selection], [[0, alpha]], 'beta is hidden by the filter now, so it does not come back');
 assert.equal('exclude' in state, false);
 // Reloaded while the results were up: nothing is restored.
 update({filter: '', selection: new Map([[0, alpha]])});
 showResults();
 update({generation: state.generation + 1});
 closeResults();
 assert.equal(state.selection.size, 0);
 update({session: null, searchResults: null, filter: ''});
});
