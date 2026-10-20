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
// `trace` records focus and click in the ORDER they happened, which is the whole
// of finding #18: the click must not be dispatched before focus has somewhere
// visible to land.
const trace = [];
class Node {
 constructor(id = '') { this.id = id; this.attrs = {}; this.children = []; this.textContent = ''; this.disabled = false; this.title = ''; this.hidden = false; this.classes = new Set(); this.listeners = {}; this.clicks = 0; this.focuses = 0;
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
 click() { this.clicks++; trace.push(`click ${this.id}`); }
 focus() { this.focuses++; trace.push(`focus ${this.id}`); }
}
const nodes = new Map();
const $ = sel => { if (!nodes.has(sel)) nodes.set(sel, new Node(sel)); return nodes.get(sel); };
globalThis.document = {querySelector: $, createElement: () => new Node(), addEventListener() {}, activeElement: null};
globalThis.window = {addEventListener() {}, innerWidth: 0};

const {
 ACCEPTANCE_WIDTHS, COMPACT_BREAKPOINT, COMPACT_EXTRA, FOLD_ORDER, OVERFLOW_BREAKPOINT,
 PRIMARY, SECONDARY, WIDE_RUNGS, labelFor, mirrorOf, overflowFor, syncOverflow,
} = await import('./static/js/narrow.js');

const html = readFileSync(new URL('./static/index.html', import.meta.url), 'utf8');
const css = readFileSync(new URL('./static/app.css', import.meta.url), 'utf8');
const toolbarHTML = () => {
 const toolbar = html.match(/<nav id="toolbar"[\s\S]*?<\/nav>/);
 assert.ok(toolbar);
 return toolbar[0];
};
const toolbarIds = () => [...toolbarHTML().matchAll(/id="(btn[A-Za-z]+)"/g)].map(m => m[1]);
const pathbarHTML = () => {
 const bar = html.match(/<div class="pathbar">[\s\S]*?<\/div>/);
 assert.ok(bar, 'the path bar exists');
 return bar[0];
};

// --- membership at every width (M4 §9.5; stabilization contract §4.1) --------

const FOUR = ['btnView', 'btnProps', 'btnPerms', 'btnRename'];
const SIX = [...FOUR, 'btnCopy', 'btnMove'];
// What ⋯ holds at each acceptance size, in the order the menu lists it — the
// toolbar's own left-to-right order.
const TWO = ['btnView', 'btnProps'];
const AT = {1280: TWO, 1024: FOUR, 900: SIX, 768: SECONDARY, 375: [...SECONDARY, ...COMPACT_EXTRA]};

test('every acceptance width has its stated membership', () => {
 assert.deepEqual(Object.keys(AT).map(Number).sort((a, b) => b - a), ACCEPTANCE_WIDTHS, 'the table covers exactly the acceptance widths');
 for (const width of ACCEPTANCE_WIDTHS) assert.deepEqual(overflowFor(width), AT[width], `${width}px`);
});

test('the 768 px rung collapses the secondary actions', () => {
 assert.deepEqual(overflowFor(OVERFLOW_BREAKPOINT), SECONDARY, '768 is inside the contract, not outside it');
 assert.deepEqual(overflowFor(768), SECONDARY);
});

test('the wide rungs fold at their stated edges and nothing folds above them', () => {
 assert.deepEqual(overflowFor(1920), []);
 assert.deepEqual(overflowFor(1301), [], 'nothing folds above 1,300');
 assert.deepEqual(overflowFor(1300), TWO);
 assert.deepEqual(overflowFor(1280), TWO, 'View text and Properties give way at 1280, for a wider font’s sake');
 assert.deepEqual(overflowFor(1131), TWO);
 assert.deepEqual(overflowFor(1130), FOUR);
 assert.deepEqual(overflowFor(961), FOUR);
 assert.deepEqual(overflowFor(960), SIX);
 assert.deepEqual(overflowFor(769), SIX);
});

test('narrowing the window only ever folds more; it never brings an action back', () => {
 let wider = new Set();
 for (let width = 1920; width >= 1; width--) {
  const here = new Set(overflowFor(width));
  for (const id of wider) assert.ok(here.has(id), `${id} came back onto the bar at ${width}px`);
  wider = here;
 }
});

test('the wide rungs fold only secondary actions, each once, listed in toolbar order', () => {
 assert.equal(new Set(FOLD_ORDER).size, FOLD_ORDER.length, 'no action folds twice');
 for (const id of FOLD_ORDER) assert.ok(SECONDARY.includes(id), `${id} folds above 768px but is not a secondary action`);
 for (let i = 1; i < WIDE_RUNGS.length; i++) {
  assert.ok(WIDE_RUNGS[i].max < WIDE_RUNGS[i - 1].max, 'the rungs are listed widest first');
  assert.ok(WIDE_RUNGS[i].fold > WIDE_RUNGS[i - 1].fold, 'a narrower rung folds more');
 }
 assert.ok(WIDE_RUNGS.at(-1).max > OVERFLOW_BREAKPOINT, 'the 768 px rung stays the contract’s own');
 assert.ok(WIDE_RUNGS.at(-1).fold <= FOLD_ORDER.length);
 for (let width = OVERFLOW_BREAKPOINT + 1; width <= 1920; width++) {
  const menu = overflowFor(width);
  assert.deepEqual(menu, SECONDARY.filter(id => menu.includes(id)), `the menu is in toolbar order at ${width}px`);
 }
});

// --- the bar as measured (stabilization contract §4.1) -----------------------
//
// Widths of each control's box, measured 2026-10-20/21 in Chromium on Windows —
// system-ui is Segoe UI there — at 14 px, with this stylesheet's toolbar rules
// (button padding .5rem, gap .3rem, side padding .75rem). The model adds them
// up the way flexbox does: every in-flow item, one gap between each pair (⋯'s
// empty wrapper is an item even while ⋯ is hidden), and the padding. It is
// checked against the browser's own sums below, and it is what keeps
// WIDE_RUNGS honest: a rung changed without re-measuring fails here, not on
// someone's screen. Another platform's system font is wider or narrower than
// Segoe UI; the spare room is the allowance for that, and the bar wraps rather
// than clips if it runs out.
//
// The WIDEST state is the one that matters: after a search, whose button reads
// "Results (N)" — at most "Results (1,000)", since search stops at 1,000 hits —
// and stays on the bar while there are results to go back to. The plain state
// is before any search. `download` is the split (the button and its ▾); it is
// as wide as "Download as ZIP" in both states and whatever label it shows,
// because app.css reserves that width (the test after the model).
const MEASURED = {
 btnTree: 62.8, btnMkdir: 86.2, btnUpload: 62.8, download: 146.8, btnView: 74.6,
 btnProps: 80.7, btnPerms: 90.3, btnRename: 67.7, btnCopy: 76.9, btnMove: 79.9, btnDelete: 57.9,
 btnSearch: 69.4, btnResults: 106.7, btnTrash: 50, btnJobs: 86.3, btnShortcuts: 24.3, btnMore: 30,
};
// SPARE is the room the widest bar keeps at the acceptance widths — 900 has
// least, 45 px; 1280 has 158 — and PLAIN_SPARE the room before any search (156
// at least); both are the allowance for a system font wider than Segoe UI.
const GAP = 4.8, EDGES = 24, SPARE = 40, PLAIN_SPARE = 150;
// The drawer toggle is on the bar at and below 960 px (app.css hides it from
// 60.0625rem up), which the last test in this group checks against the CSS.
const FOLDERS_FROM = 960;
function barWidth(width, folded = overflowFor(width), {widest = true} = {}) {
 const out = new Set(folded);
 const items = [
  ...(width <= FOLDERS_FROM ? ['btnTree'] : []),
  'btnMkdir', 'btnUpload', 'download', 'btnView', 'btnProps', 'btnPerms', 'btnRename', 'btnCopy', 'btnMove', 'btnDelete',
  'btnSearch', ...(widest ? ['btnResults'] : []), 'btnTrash', 'btnJobs', 'btnShortcuts', 'moreSplit',
 ].filter(id => !out.has(id));
 const size = id => id === 'moreSplit' ? (out.size ? MEASURED.btnMore : 0) : MEASURED[id];
 return items.reduce((total, id) => total + size(id), 0) + GAP * (items.length - 1) + EDGES;
}

test('the model reproduces what the browser measured', () => {
 // The browser's max-content widths of the whole bar, widest and plain, the
 // same with either Download label.
 const near = (got, want, what) => assert.ok(Math.abs(got - want) <= 1, `${what}: model ${got.toFixed(1)}px, browser ${want}px`);
 near(barWidth(1301), 1256.5, 'above 1300, nothing folded');
 near(barWidth(1301, overflowFor(1301), {widest: false}), 1145, 'above 1300 plain');
 near(barWidth(1280), 1121.6, '1280, two folded');
 near(barWidth(1280, overflowFor(1280), {widest: false}), 1010.1, '1280 plain');
 near(barWidth(1024), 954, '1024, four folded');
 near(barWidth(1024, overflowFor(1024), {widest: false}), 842.4, '1024 plain');
 near(barWidth(900), 855.2, '900, six folded and Folders');
 near(barWidth(900, overflowFor(900), {widest: false}), 743.7, '900 plain');
});

test('selecting never changes the bar: the Download button keeps its longer label’s width', () => {
 // list.js relabels the button with the selection. Had its width followed the
 // label, the bar could rewrap between a row's mousedown and mouseup and move
 // the row out from under the pointer, so the click selected nothing.
 const listSource = readFileSync(new URL('./static/js/list.js', import.meta.url), 'utf8');
 const assignment = listSource.match(/\$\('#btnDownload'\)\.textContent\s*=([^;]*);/);
 assert.ok(assignment, 'list.js sets the Download label in one statement');
 const labels = [...assignment[1].matchAll(/'(Download[^']*)'/g)].map(m => m[1]);
 assert.ok(labels.length >= 2, `the labels it chooses between: ${labels.join(', ')}`);
 const longest = labels.reduce((a, b) => b.length > a.length ? b : a);
 const rule = css.match(/#btnDownload::after \{([^}]*)\}/);
 assert.ok(rule, 'the button reserves a width');
 assert.ok(rule[1].includes(`content:'${longest}' / '';`), `it reserves "${longest}", with an empty alternative so it is no part of the name`);
 assert.ok(rule[1].includes(`content:'${longest}';`), 'and the same reserve for a browser without that syntax');
 for (const declaration of ['display:block', 'height:0', 'overflow:hidden', 'visibility:hidden', 'white-space:nowrap']) {
  assert.ok(rule[1].includes(declaration), `the reserve takes width and nothing else: ${declaration}`);
 }
});

test('at 1280, 1024 and 900 px the bar fits one row before and after a search, with room to spare', () => {
 for (const width of [1280, 1024, 900]) {
  const widest = barWidth(width), plain = barWidth(width, overflowFor(width), {widest: false});
  assert.ok(widest <= width - SPARE, `${width}px: the bar after a search needs ${widest.toFixed(1)}px`);
  assert.ok(plain <= width - PLAIN_SPARE, `${width}px: the bar before one needs ${plain.toFixed(1)}px`);
 }
});

test('at each of those widths no more is folded than the room needs', () => {
 // One action fewer in ⋯ would leave less than the spare room — so each fold
 // at 1024 and 900 is needed, which is §4.1's "only when needed". 1280 folds
 // two where one would keep SPARE, by choice (conductor, 2026-10-21): two leave
 // a system font about 20% wider than Segoe UI room after a search, one would
 // leave about 9%. Folding none is not an option there; it leaves 23 px.
 for (const width of [1024, 900]) {
  const folded = overflowFor(width);
  const fewer = FOLD_ORDER.slice(0, folded.length - 1);
  assert.ok(barWidth(width, fewer) > width - SPARE, `${width}px folds ${folded.length} where ${fewer.length} would do`);
 }
 assert.ok(barWidth(1280, []) > 1280 - SPARE, 'at 1280 the full bar would not keep the spare room');
});

test('every width above 768 fits the plain bar, and from 856 the widest one', () => {
 // Between 769 and 855 px the widest state (a search's Results showing) is a
 // row too long for six folded actions, and it wraps; the plain bar fits
 // there. Folding two more to cover it would take Upload and New folder away
 // from every 800 px window. The Results button comes and goes with a search,
 // never with a click on a row, so it cannot rewrap the bar under the pointer.
 for (let width = OVERFLOW_BREAKPOINT + 1; width <= 1920; width++) {
  const plain = barWidth(width, overflowFor(width), {widest: false});
  assert.ok(plain <= width, `${width}px plain: ${plain.toFixed(1)}px`);
  if (width >= 856) assert.ok(barWidth(width) <= width, `${width}px widest: ${barWidth(width).toFixed(1)}px`);
 }
 assert.ok(barWidth(855) > 855, 'the stated exception is real, so the comment above stays true');
});

test('the 960 px rung is where Folders joins the bar', () => {
 const rule = css.match(/@media\(min-width:([\d.]+)rem\)\s*\{\s*#btnTree\s*\{\s*display:none;\s*\}\s*\}/);
 assert.ok(rule, 'the Folders button is hidden above the drawer breakpoint by one rule');
 const hiddenFrom = Number(rule[1]) * 16;
 assert.equal(Math.ceil(hiddenFrom) - 1, FOLDERS_FROM, 'Folders shows from 960 px down, where the 60rem drawer starts');
 assert.ok(WIDE_RUNGS.some(rung => rung.max === FOLDERS_FROM), 'and a rung makes room for it there');
 assert.match(css, /@media\(max-width:60rem\)\s*\{\s*#tree \{ display:none;/, 'the drawer breakpoint the button serves');
});

// --- the path bar took navigation, the filter and Hidden (§4.1) ---------------

test('navigation, the filter and Hidden live in the path bar, under their old ids', () => {
 const bar = pathbarHTML(), tools = toolbarHTML();
 for (const id of ['btnBack', 'btnFwd', 'btnUp', 'btnRefresh', 'crumbs', 'pathEdit', 'searchBox', 'chkHidden']) {
  assert.match(bar, new RegExp(`id="${id}"`), `#${id} is in the path bar`);
  assert.doesNotMatch(tools, new RegExp(`id="${id}"`), `#${id} left the toolbar`);
 }
 // Glyph-only buttons are named: "←" is not a name a screen reader can say.
 for (const [id, name] of [['btnBack', 'Back'], ['btnFwd', 'Forward'], ['btnUp', 'Parent folder'], ['btnRefresh', 'Refresh']]) {
  assert.match(bar, new RegExp(`<button id="${id}"[^>]*aria-label="${name}"`), id);
 }
 // Their shortcuts stay in their titles, where they always were.
 assert.match(bar, /id="btnBack" title="Back \(Alt\+Left\)"/);
 assert.match(bar, /id="btnRefresh" title="Refresh \(F5\)"/);
});

test('⋯ is the last control on the bar, and its menu hangs from the bar’s right edge', () => {
 assert.equal(toolbarIds().at(-1), 'btnMore', 'nothing follows ⋯ on the row');
 assert.match(css, /#toolbar \{ position:relative;/, 'the toolbar is the menu’s containing block');
 assert.match(css, /#moreMenu \{ position:absolute; top:100%; right:\.5rem;/);
 assert.match(css, /\.moreSplit \{ display:inline-flex; \}/, '⋯’s wrapper is not positioned, so the menu ignores where ⋯ wrapped to');
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

// Finding #18: below 768 px, More → New folder closed the menu — hiding the menu
// item that had focus — and then clicked the toolbar button, which is
// `display:none` at this width. openDialog records document.activeElement as the
// control to return focus to, so the dialog's return target was something
// invisible. The ⋯ button is the visible control the user pressed, and focus goes
// there BEFORE the click, so it is what is recorded and what focus comes back to.
test('a menu item hands focus to the ⋯ button before it presses the hidden one', () => {
 window.innerWidth = 375;
 const mkdir = $('#btnMkdir');
 mkdir.textContent = 'New folder'; mkdir.disabled = false;
 syncOverflow();
 const more = $('#btnMore'), menu = $('#moreMenu');
 menu.hidden = false;
 const item = menu.children.find(child => child.attrs['data-for'] === 'btnMkdir');
 assert.ok(item);
 trace.length = 0;
 const clicks = mkdir.clicks;
 item.listeners.click();
 assert.equal(menu.hidden, true, 'the menu still closes');
 assert.equal(mkdir.clicks, clicks + 1, 'and the real button is still the one pressed');
 assert.deepEqual(trace, ['focus #btnMore', 'click #btnMkdir'],
  'focus must land on the visible ⋯ button before the dialog records its opener');
 assert.ok(more.focuses > 0);
});

test('above the rung the menu is emptied and the ⋯ button goes away', () => {
 // 1366, a common laptop width above every rung (1280 folds two since §4.1).
 window.innerWidth = 1366;
 syncOverflow();
 assert.equal($('#moreMenu').children.length, 0);
 assert.equal($('#btnMore').hidden, true);
 assert.equal($('#btnRename').classes.has('inOverflow'), false);
 window.innerWidth = 0;
});
