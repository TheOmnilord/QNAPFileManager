// Run with: node --test internal/web/search_session_test.mjs
//
// Astra r5 on the QKVM fix: "Include mounted sub-folders" is ticked in the
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
const {initSearch, openSearch, SEARCH_CROSS_DEFAULT} = await import('./static/js/search.js');

// The page as index.html builds it: the row visible, the box ticked.
$('#searchCrossRow').hidden = false;
$('#searchCross').checked = true;
initSearch();

const alice = family => ({user: 'alice', uid: 1000, gid: 100, family, authenticated: true, canWrite: true});
const bob = family => ({user: 'bob', uid: 1001, gid: 100, family, authenticated: true, canWrite: true});
const reopen = () => { $('#dlgSearch').close(); openSearch(); };

test('SEARCH_CROSS_DEFAULT is the markup’s own default', () => {
 const html = readFileSync(new URL('./static/index.html', import.meta.url), 'utf8');
 assert.equal(/<input type="checkbox" id="searchCross" checked>/.test(html), SEARCH_CROSS_DEFAULT);
 assert.equal(SEARCH_CROSS_DEFAULT, true);
});

for (const family of ['qts', 'quts_hero']) {
 test(`${family}: the box is ticked on first load, kept through the session, and ticked again for the next one`, () => {
  // connect(): the door first, with no session yet — the transient that used to
  // clear the box — then the session itself.
  update({session: null});
  update({listener: 'qts'});
  update({session: alice(family)});
  reopen();
  assert.equal($('#searchCrossRow').hidden, false, 'the box is offered');
  assert.equal($('#searchCross').checked, true, 'first open after a page load must be ticked');

  // A deliberate untick is the user's, for this session: kept on reopen, and
  // kept through a same-user refresh (the minute poll, a read-only toggle).
  $('#searchCross').checked = false;
  reopen();
  assert.equal($('#searchCross').checked, false);
  update({session: {...alice(family), canWrite: false}});
  reopen();
  assert.equal($('#searchCross').checked, false, 'a refresh is not a new session');

  // Sign-out and sign-in: back to the default, not to off.
  update({session: null});
  assert.equal(state.session, null);
  update({session: alice(family)});
  reopen();
  assert.equal($('#searchCross').checked, true, 'a fresh session starts at the default');

  // A switch of user is a fresh session too.
  $('#searchCross').checked = false;
  update({session: bob(family)});
  reopen();
  assert.equal($('#searchCross').checked, true, 'the next user does not inherit the untick');
  $('#dlgSearch').close();
 });
}
