// Run with: node --test internal/web/keys_test.mjs
//
// M4 contract §9.4: the keyboard map in #dlgShortcuts is AUTHORITATIVE, and a
// shortcut cannot be added, removed or re-bound without the dialog changing.
// Three things are cross-checked here, in the shape of the Go element-id and
// route contract tests:
//
//   the dialog's table  ←→  KEYMAP  ←→  the handlers that implement it
//
// The app-scope half is checked against the real binding table appBindings()
// returns. The list-scope half is checked against list.js's own switch, read
// from source — the same technique the Go side uses over the embedded assets,
// and the only honest way to assert "this row has a handler" for a handler
// that cannot be imported without a DOM.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import {KEYMAP, LISTING_CHORDS, LISTING_PAUSED_MESSAGE, WHERE, appBindings, chordOf, dispatchKey, keymapRows} from './static/js/keys.js';

const html = readFileSync(new URL('./static/index.html', import.meta.url), 'utf8');
const listSource = readFileSync(new URL('./static/js/list.js', import.meta.url), 'utf8');

// The dialog's rows, parsed out of the embedded shell.
function dialogRows() {
 const table = html.match(/<table id="shortcutsTable">[\s\S]*?<\/table>/);
 assert.ok(table, '#dlgShortcuts must carry the map as a table');
 const body = table[0].match(/<tbody>([\s\S]*?)<\/tbody>/);
 assert.ok(body, 'the map needs a tbody');
 return [...body[1].matchAll(/<tr><th scope="row">(.*?)<\/th><td>(.*?)<\/td><td>(.*?)<\/td><\/tr>/g)]
  .map(m => ({keys: m[1], what: m[2], where: m[3]}));
}

// A table of stubs: appBindings' collaborators, each recording that it ran.
function stubs() {
 const calls = [];
 const record = name => (...args) => calls.push([name, ...args]);
 return {
  calls,
  deps: {
   editPath: record('editPath'), openSearch: record('openSearch'), openShortcuts: record('openShortcuts'),
   markClipboard: record('markClipboard'), pasteHere: record('pasteHere'), deleteSelection: record('deleteSelection'),
   openPerms: record('openPerms'), refresh: record('refresh'), parent: record('parent'),
   back: record('back'), forward: record('forward'), toggleHidden: record('toggleHidden'),
   focusFilter: record('focusFilter'), escape: record('escape'), textSelected: () => false,
  },
 };
}
const event = (key, extra = {}) => ({key, preventDefault() { this.defaulted = true; }, target: {matches: () => false}, ...extra});

test('the Shortcuts dialog and KEYMAP are the same table, row for row', () => {
 assert.deepEqual(dialogRows(), keymapRows());
});

test('every app-scope row is a real binding, and every binding is a row', () => {
 const bindings = appBindings(stubs().deps);
 const rows = KEYMAP.filter(row => row.scope === 'app').map(row => row.chord);
 assert.deepEqual([...bindings.keys()].sort(), [...rows].sort());
 for (const chord of rows) assert.equal(typeof bindings.get(chord).run, 'function', chord);
});

test('every list-scope row is implemented by a case in list.js, and every case is a row', () => {
 const handler = listSource.slice(listSource.indexOf("$('#list').addEventListener('keydown'"));
 assert.ok(handler.length > 0, 'the list keydown handler must exist');
 const cases = new Set([...handler.matchAll(/case '(.*?)':/g)].map(m => m[1]));
 const rows = KEYMAP.filter(row => row.scope === 'list');
 const claimed = new Set(rows.flatMap(row => row.cases));
 for (const row of rows) {
  for (const key of row.cases) assert.ok(cases.has(key), `the dialog promises ${row.keys} but list.js has no case '${key}'`);
 }
 for (const key of cases) assert.ok(claimed.has(key), `list.js handles '${key}' and the dialog says nothing about it`);
});

test('every row says what it does and where, and no chord is bound twice', () => {
 const seen = new Set();
 for (const row of KEYMAP) {
  assert.ok(row.keys.trim().length > 0);
  assert.ok(row.what.trim().length > 0, row.keys);
  assert.ok(WHERE[row.scope], row.scope);
  if (row.scope !== 'app') continue;
  assert.ok(!seen.has(row.chord), `${row.chord} is bound twice`);
  seen.add(row.chord);
 }
});

test('chordOf spells a press the way the table does', () => {
 assert.equal(chordOf({key: 'f', ctrlKey: true}), 'Ctrl+F');
 assert.equal(chordOf({key: 'F', ctrlKey: true, shiftKey: true}), 'Ctrl+Shift+F', 'a modified press keeps its Shift');
 assert.equal(chordOf({key: 'c', metaKey: true}), 'Ctrl+C', 'a Mac user’s Cmd+C is a copy');
 assert.equal(chordOf({key: 'ArrowLeft', altKey: true}), 'Alt+ArrowLeft');
 assert.equal(chordOf({key: 'F10', shiftKey: true}), 'Shift+F10');
 assert.equal(chordOf({key: '?'}), '?', 'the shifted slash is one key, not two');
 assert.equal(chordOf({key: '/'}), '/');
 assert.equal(chordOf({key: 'Delete'}), 'Delete');
 assert.equal(chordOf({}), '');
});

test('a dialog swallows every shortcut', () => {
 const {deps, calls} = stubs();
 assert.equal(dispatchKey(event('Delete'), appBindings(deps), {dialogOpen: true}), 'ignored');
 assert.deepEqual(calls, []);
});

test('typing takes the keys, except the two that are meant to work from a field', () => {
 const {deps, calls} = stubs();
 const bindings = appBindings(deps);
 assert.equal(dispatchKey(event('Delete'), bindings, {editing: true}), 'ignored');
 assert.equal(dispatchKey(event('c', {ctrlKey: true}), bindings, {editing: true}), 'ignored');
 assert.deepEqual(calls, [], 'a key that means "copy" is never taken from where the user is typing');
 assert.equal(dispatchKey(event('l', {ctrlKey: true}), bindings, {editing: true}), 'ran');
 assert.equal(dispatchKey(event('f', {ctrlKey: true}), bindings, {editing: true}), 'ran');
 assert.deepEqual(calls.map(c => c[0]), ['editPath', 'openSearch']);
});

test('while the results cover the listing, the listing chords do nothing and say so', () => {
 const {deps, calls} = stubs();
 const bindings = appBindings(deps);
 const said = [];
 for (const chord of LISTING_CHORDS) {
  const key = chord === 'Delete' ? 'Delete' : chord.slice(-1).toLowerCase();
  const ev = event(key, chord === 'Delete' ? {} : {ctrlKey: true});
  assert.equal(dispatchKey(ev, bindings, {listingMutable: false, announce: m => said.push(m)}), 'paused', chord);
  assert.equal(ev.defaulted, true, `${chord} must not also reach the browser`);
 }
 assert.deepEqual(calls, [], 'nothing acted on rows nobody can see');
 assert.deepEqual([...new Set(said)], [LISTING_PAUSED_MESSAGE]);
 // A chord that is not about the listing still works while the results are up.
 assert.equal(dispatchKey(event('f', {ctrlKey: true}), bindings, {listingMutable: false}), 'ran');
});

test('a text selection leaves the clipboard chords to the browser', () => {
 const {deps, calls} = stubs();
 deps.textSelected = () => true;
 const bindings = appBindings(deps);
 const ev = event('c', {ctrlKey: true});
 assert.equal(dispatchKey(ev, bindings, {}), 'ran');
 assert.equal(ev.defaulted, undefined, 'the browser’s own copy must still happen');
 assert.deepEqual(calls, []);
});

test('each binding runs the thing its row promises', () => {
 const {deps, calls} = stubs();
 const bindings = appBindings(deps);
 const expected = [
  ['Ctrl+L', 'editPath'], ['Ctrl+F', 'openSearch'], ['Ctrl+H', 'toggleHidden'], ['Delete', 'deleteSelection'],
  ['F9', 'openPerms'], ['F5', 'refresh'], ['Backspace', 'parent'], ['Alt+ArrowLeft', 'back'],
  ['Alt+ArrowRight', 'forward'], ['/', 'focusFilter'], ['?', 'openShortcuts'], ['Escape', 'escape'],
  ['Ctrl+V', 'pasteHere'],
 ];
 for (const [chord, name] of expected) {
  calls.length = 0;
  bindings.get(chord).run(event('x'));
  assert.equal(calls[0]?.[0], name, chord);
 }
 calls.length = 0;
 bindings.get('Ctrl+C').run(event('c'));
 bindings.get('Ctrl+X').run(event('x'));
 assert.deepEqual(calls, [['markClipboard', 'copy'], ['markClipboard', 'move']]);
});

test('the browser’s own Ctrl+Shift chords are NOT this app’s clipboard (round 2, finding 1)', () => {
 const {deps, calls} = stubs();
 const bindings = appBindings(deps);
 // Ctrl+Shift+V is paste-without-formatting, Ctrl+Shift+C opens the inspector,
 // Ctrl+Shift+X is the browser's. None of them is a file operation.
 for (const key of ['v', 'c', 'x']) {
  const chord = chordOf(event(key, {ctrlKey: true, shiftKey: true}));
  assert.equal(chord, `Ctrl+Shift+${key.toUpperCase()}`);
  assert.equal(bindings.has(chord), false, `${chord} must be the browser's`);
  const ev = event(key, {ctrlKey: true, shiftKey: true});
  assert.equal(dispatchKey(ev, bindings, {}), 'ignored', chord);
  assert.equal(ev.defaulted, undefined, `${chord} must reach the browser untouched`);
 }
 assert.deepEqual(calls, []);
 // The plain chords still bind, and still do their own work.
 for (const [key, name] of [['c', 'markClipboard'], ['x', 'markClipboard'], ['v', 'pasteHere']]) {
  calls.length = 0;
  const ev = event(key, {ctrlKey: true});
  assert.equal(dispatchKey(ev, bindings, {}), 'ran', key);
  assert.equal(calls[0]?.[0], name, key);
  assert.equal(ev.defaulted, true);
 }
 // Shift+Delete stays unbound, exactly as the map documents.
 assert.equal(chordOf(event('Delete', {shiftKey: true})), 'Shift+Delete');
 assert.equal(bindings.has('Shift+Delete'), false);
 // A shifted printable with no modifier is still one key: '?' is not 'Shift+?'.
 assert.equal(chordOf(event('?', {shiftKey: true})), '?');
 assert.equal(bindings.has('?'), true);
});

test('Ctrl+R is never bound, and the map says why', () => {
 assert.equal(appBindings(stubs().deps).has('Ctrl+R'), false);
 const row = KEYMAP.find(r => r.keys === 'Ctrl+R');
 assert.ok(row, 'the map documents the one chord the app deliberately leaves alone');
 assert.match(row.what, /never intercepted/);
});
