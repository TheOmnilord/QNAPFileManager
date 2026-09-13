// Run with: node --test internal/web/narrow_test.mjs
//
// M4 contract §9.5: ≤ 768 px is the contract, not an aspiration, and at each of
// the five acceptance sizes every toolbar action must still be REACHABLE.
// Before M4, #btnMkdir and #btnUpload were display:none below 46rem — function
// removed, with nothing said. The rule is now data, so the five sizes are a
// table test rather than five screenshots.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
// A document double, so syncOverflow — the DOM half — can be exercised too.
class Node {
 constructor() { this.attrs = {}; this.children = []; this.textContent = ''; this.disabled = false; this.title = ''; this.hidden = false; this.classes = new Set(); this.listeners = {}; this.clicks = 0;
  this.classList = {toggle: (n, on) => on ? this.classes.add(n) : this.classes.delete(n), add: n => this.classes.add(n), remove: n => this.classes.delete(n), contains: n => this.classes.has(n)};
 }
 setAttribute(k, v) { this.attrs[k] = String(v); }
 getAttribute(k) { return this.attrs[k] ?? null; }
 append(...kids) { this.children.push(...kids); }
 replaceChildren(...kids) { this.children = kids; }
 addEventListener(type, fn) { this.listeners[type] = fn; }
 querySelector() { return null; }
 querySelectorAll() { return []; }
 contains() { return false; }
 click() { this.clicks++; }
 focus() {}
}
const nodes = new Map();
const $ = sel => { if (!nodes.has(sel)) nodes.set(sel, new Node()); return nodes.get(sel); };
globalThis.document = {querySelector: $, createElement: () => new Node(), addEventListener() {}, activeElement: null};
globalThis.window = {addEventListener() {}, innerWidth: 0};

const {
 ACCEPTANCE_WIDTHS, COMPACT_BREAKPOINT, COMPACT_EXTRA, OVERFLOW_BREAKPOINT,
 PRIMARY, SECONDARY, labelFor, mirrorOf, overflowFor, syncOverflow,
} = await import('./static/js/narrow.js');

const html = readFileSync(new URL('./static/index.html', import.meta.url), 'utf8');
const css = readFileSync(new URL('./static/app.css', import.meta.url), 'utf8');
const toolbarIds = () => {
 const toolbar = html.match(/<nav id="toolbar"[\s\S]*?<\/nav>/);
 assert.ok(toolbar);
 return [...toolbar[0].matchAll(/id="(btn[A-Za-z]+)"/g)].map(m => m[1]);
};

test('the wide sizes collapse nothing; the 768 px rung collapses the secondary actions', () => {
 assert.deepEqual(overflowFor(1280), []);
 assert.deepEqual(overflowFor(1024), []);
 assert.deepEqual(overflowFor(900), []);
 assert.deepEqual(overflowFor(769), []);
 assert.deepEqual(overflowFor(OVERFLOW_BREAKPOINT), SECONDARY, '768 is inside the contract, not outside it');
 assert.deepEqual(overflowFor(768), SECONDARY);
});

test('a phone-width screen collapses the secondary actions and the two extras', () => {
 assert.deepEqual(overflowFor(375), [...SECONDARY, ...COMPACT_EXTRA]);
 assert.deepEqual(overflowFor(COMPACT_BREAKPOINT), [...SECONDARY, ...COMPACT_EXTRA]);
 assert.deepEqual(overflowFor(481), SECONDARY);
});

test('at every acceptance size, every toolbar action is either on the bar or in the menu', () => {
 const ids = toolbarIds();
 assert.ok(ids.includes('btnMkdir') && ids.includes('btnUpload'), 'the two that used to vanish');
 for (const width of ACCEPTANCE_WIDTHS) {
  const menu = overflowFor(width), collapsed = new Set(menu);
  assert.equal(menu.length, collapsed.size, `duplicate menu item at ${width}px`);
  for (const id of ids) {
   // A button is either on the bar or in the menu. The only failure this can
   // have — a button hidden by CSS with no menu item — is a button that is
   // collapsed without being one of the declared collapsible ones.
   if (collapsed.has(id)) assert.ok(SECONDARY.includes(id) || COMPACT_EXTRA.includes(id), `${id} collapsed at ${width}px with no menu item`);
  }
 }
 // The two the old CSS removed outright are in the menu at the narrowest size.
 const narrowest = overflowFor(Math.min(...ACCEPTANCE_WIDTHS));
 assert.ok(narrowest.includes('btnMkdir') && narrowest.includes('btnUpload'), 'New folder and Upload stay reachable at 375px');
});

test('no action is both primary and collapsible — that would be hidden with no menu item', () => {
 for (const id of [...SECONDARY, ...COMPACT_EXTRA]) assert.ok(!PRIMARY.includes(id), id);
 assert.equal(new Set([...SECONDARY, ...COMPACT_EXTRA]).size, SECONDARY.length + COMPACT_EXTRA.length, 'no id collapses twice');
});

test('every collapsible and primary id exists in the shell', () => {
 const ids = new Set([...toolbarIds(), 'btnMore']);
 for (const id of [...SECONDARY, ...COMPACT_EXTRA, ...PRIMARY]) assert.ok(ids.has(id), `#${id} is not in the toolbar`);
});

test('the CSS no longer hides the two actions it used to remove', () => {
 const narrow = css.match(/@media\(max-width:46rem\)\s*\{[^}]*\}/);
 assert.ok(narrow, 'the 46rem block still exists');
 assert.ok(!/#btnMkdir[^}]*display:none/.test(narrow[0]), 'New folder must be relocated, never removed');
 assert.ok(!/#btnUpload[^}]*display:none/.test(narrow[0]), 'Upload must be relocated, never removed');
 assert.match(css, /\.inOverflow\s*\{\s*display:none;\s*\}/, 'the class the menu uses to relocate a button');
 assert.match(css, /@media\(max-width:48rem\)/, '48rem is the explicit 768 px rung');
});

test('the shell carries the ⋯ button and its menu, both labelled', () => {
 assert.match(html, /id="btnMore"[^>]*aria-haspopup="menu"/);
 assert.match(html, /id="btnMore"[^>]*aria-expanded="false"/);
 assert.match(html, /id="btnMore"[^>]*aria-label="More actions"/);
 assert.match(html, /id="moreMenu"[^>]*role="menu"[^>]*aria-label="More actions"/);
});

test('a menu item is named by its button, except where the button has no useful text', () => {
 assert.equal(labelFor('btnMkdir', 'New folder'), 'New folder');
 assert.equal(labelFor('btnShortcuts', '?'), 'Keyboard shortcuts', 'an icon-only control needs a name');
 assert.equal(labelFor('btnRefresh', '↻'), 'Refresh');
 assert.equal(labelFor('btnDelete', '  Delete  '), 'Delete');
 assert.equal(labelFor('btnDelete', ''), 'btnDelete', 'never an empty menu item');
});

test('a width nobody measured (a document with no layout) collapses nothing', () => {
 assert.deepEqual(overflowFor(0), []);
 assert.deepEqual(overflowFor(undefined), []);
 assert.deepEqual(overflowFor(NaN), []);
});

// --- the menu item mirrors ALL FOUR spellings (round-1 finding 3) ------------

test('mirrorOf copies the describedby as well as the title and the disabled state', () => {
 assert.deepEqual(mirrorOf({disabled: true, title: 'Select a file or folder first.', describedBy: 'why-btnRename'}),
  {disabled: true, ariaDisabled: 'true', title: 'Select a file or folder first.', describedBy: 'why-btnRename'});
 assert.deepEqual(mirrorOf({}), {disabled: false, ariaDisabled: 'false', title: '', describedBy: ''});
 assert.deepEqual(mirrorOf(), {disabled: false, ariaDisabled: 'false', title: '', describedBy: ''});
});

test('a collapsed action’s menu item says exactly what the button it stands for says', () => {
 // One disabled button with a reason, one enabled one, at a width that collapses.
 window.innerWidth = 375;
 const rename = $('#btnRename');
 rename.textContent = 'Rename'; rename.disabled = true; rename.title = 'Select a file or folder first.';
 rename.setAttribute('aria-describedby', 'why-btnRename');
 const mkdir = $('#btnMkdir');
 mkdir.textContent = 'New folder'; mkdir.disabled = false; mkdir.title = 'New folder';
 mkdir.setAttribute('aria-describedby', 'why-btnMkdir');

 syncOverflow();

 const items = new Map($('#moreMenu').children.map(item => [item.attrs['data-for'], item]));
 const renamed = items.get('btnRename');
 assert.ok(renamed, 'the collapsed action has a menu item');
 assert.equal(renamed.disabled, true);
 assert.equal(renamed.attrs['aria-disabled'], 'true');
 assert.equal(renamed.title, 'Select a file or folder first.');
 assert.equal(renamed.attrs['aria-describedby'], 'why-btnRename',
  'a menu item that drops the description says nothing to the reader it was added for');
 const created = items.get('btnMkdir');
 assert.equal(created.disabled, false);
 assert.equal(created.attrs['aria-disabled'], 'false');
 assert.equal(created.attrs['aria-describedby'], 'why-btnMkdir');
 assert.equal(created.textContent, 'New folder');
 // The button is relocated, not removed: it carries the class and the menu
 // item presses the real button.
 assert.equal(rename.classes.has('inOverflow'), true);
 created.listeners.click();
 assert.equal(mkdir.clicks, 1, 'the menu item is the button, not a second path');
 assert.equal($('#btnMore').hidden, false);
});

test('a button with no description gives its menu item none to copy', () => {
 window.innerWidth = 375;
 const trash = $('#btnTrash');
 trash.textContent = 'Trash'; trash.title = ''; trash.attrs = {};
 syncOverflow();
 const item = $('#moreMenu').children.find(child => child.attrs['data-for'] === 'btnTrash');
 assert.ok(item);
 assert.equal(item.attrs['aria-describedby'], undefined, 'never a dangling describedby');
 assert.equal(item.textContent, 'Trash');
});

test('above the rung the menu is emptied and the ⋯ button goes away', () => {
 window.innerWidth = 1280;
 syncOverflow();
 assert.equal($('#moreMenu').children.length, 0);
 assert.equal($('#btnMore').hidden, true);
 assert.equal($('#btnRename').classes.has('inOverflow'), false);
 window.innerWidth = 0;
});
