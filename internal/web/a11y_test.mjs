// Run with: node --test internal/web/a11y_test.mjs
//
// M4 contract §9.1–§9.3: the declared focus order, the focus trap, and the
// structural properties of the shell a screen reader depends on.
//
// What this can and cannot do is stated honestly in the contract (§9.6): there
// is no npm here, so there is no axe run. This is structural — the ARIA is
// present, the describedby resolves, no positive tabindex exists — plus the
// trap arithmetic, which is pure and therefore genuinely tested. An NVDA pass
// and a keyboard-only pass are manual items on the hardware checklist.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import {FOCUSABLE, FOCUS_ORDER, trapStep} from './static/js/a11y.js';

const html = readFileSync(new URL('./static/index.html', import.meta.url), 'utf8');
const ids = new Set([...html.matchAll(/id="([^"]+)"/g)].map(m => m[1]));
const dialogs = [...html.matchAll(/<dialog\s([^>]*)>/g)].map(m => m[1]);

test('Tab wraps at the ends of a dialog and is left alone in the middle', () => {
 const list = ['a', 'b', 'c'];
 assert.equal(trapStep(list, 'a', {key: 'Tab'}), null, 'an interior Tab is the browser’s');
 assert.equal(trapStep(list, 'b', {key: 'Tab'}), null);
 assert.deepEqual(trapStep(list, 'c', {key: 'Tab'}), {index: 0, wrapped: true});
 assert.deepEqual(trapStep(list, 'a', {key: 'Tab', shiftKey: true}), {index: 2, wrapped: true});
 assert.equal(trapStep(list, 'b', {key: 'Tab', shiftKey: true}), null);
});

test('focus that has escaped the dialog is pulled back to the right end', () => {
 const list = ['a', 'b'];
 assert.deepEqual(trapStep(list, null, {key: 'Tab'}), {index: 0, wrapped: true});
 assert.deepEqual(trapStep(list, 'elsewhere', {key: 'Tab', shiftKey: true}), {index: 1, wrapped: true});
});

test('the trap never fires on a key that is not Tab, or on a dialog with nothing focusable', () => {
 assert.equal(trapStep(['a'], 'a', {key: 'Escape'}), null, 'Esc closes; the platform owns that');
 assert.equal(trapStep(['a'], 'a', {key: 'Enter'}), null);
 assert.equal(trapStep([], null, {key: 'Tab'}), null);
 assert.equal(trapStep(null, null, {key: 'Tab'}), null);
 assert.equal(trapStep([null, undefined], null, {key: 'Tab'}), null, 'holes are not focus targets');
});

test('one focusable element is a cycle of one, not a way out', () => {
 assert.deepEqual(trapStep(['only'], 'only', {key: 'Tab'}), {index: 0, wrapped: true});
 assert.deepEqual(trapStep(['only'], 'only', {key: 'Tab', shiftKey: true}), {index: 0, wrapped: true});
});

test('the focusable selector excludes the things that must never take focus', () => {
 assert.match(FOCUSABLE, /button:not\(\[disabled\]\)/);
 assert.match(FOCUSABLE, /\[tabindex\]:not\(\[tabindex="-1"\]\)/);
});

test('the declared focus order is the shell’s source order (§9.1)', () => {
 let at = -1;
 for (const id of FOCUS_ORDER) {
  assert.ok(ids.has(id), `#${id} must exist for the declared focus order`);
  const next = html.indexOf(`id="${id}"`);
  assert.ok(next > at, `#${id} is out of the declared order`);
  at = next;
 }
});

test('no positive tabindex anywhere — source order IS focus order', () => {
 const positive = [...html.matchAll(/tabindex="(\d+)"/g)].map(m => Number(m[1])).filter(n => n > 0);
 assert.deepEqual(positive, [], 'a positive tabindex would break the declared order');
});

test('every dialog is labelled, and every describedby resolves', () => {
 assert.ok(dialogs.length >= 12, `only ${dialogs.length} dialogs found`);
 for (const attrs of dialogs) {
  const labelled = attrs.match(/aria-labelledby="([^"]+)"/);
  assert.ok(labelled, `a dialog with no aria-labelledby: ${attrs}`);
  for (const id of labelled[1].split(/\s+/)) assert.ok(ids.has(id), `aria-labelledby #${id} does not exist`);
 }
 for (const m of html.matchAll(/aria-describedby="([^"]+)"/g)) {
  for (const id of m[1].split(/\s+/)) assert.ok(ids.has(id), `aria-describedby #${id} does not exist`);
 }
});

test('the consequence sentence is what a dangerous dialog describes itself by (§9.2)', () => {
 assert.match(html, /<dialog id="dlgConfirm"[^>]*aria-describedby="confirmBody"/);
 assert.match(html, /<dialog id="dlgDelete"[^>]*aria-describedby="delBody"/);
 // #dlgConfirm autofocuses the phrase field, never OK — asserted where the
 // behaviour lives (actions.js), and kept honest here by the field's presence.
 assert.ok(ids.has('confirmPhrase') && ids.has('confirmOK'));
});

test('the list keeps its grid semantics and the live regions keep their roles', () => {
 assert.match(html, /id="list"[^>]*role="grid"/);
 assert.match(html, /id="list"[^>]*aria-multiselectable="true"/);
 assert.match(html, /id="list"[^>]*aria-rowcount=/);
 assert.match(html, /id="announce"[^>]*aria-live="polite"/);
 assert.match(html, /id="status"[^>]*role="status"/);
 assert.match(html, /id="toast"[^>]*role="status"/);
 assert.match(html, /id="signin"[^>]*role="alert"/, 'a sign-in failure interrupts; everything else is polite');
});

test('every empty state and every banner is a live region, so it is heard as well as seen', () => {
 for (const id of ['listEmpty', 'resultsEmpty', 'jobsEmpty', 'bannerReadonly', 'bannerBreakGlass']) {
  assert.ok(ids.has(id), id);
  const tag = html.match(new RegExp(`<[^>]*id="${id}"[^>]*>`));
  assert.match(tag[0], /role="status"/, `#${id} must be announced`);
 }
});

test('the icon-only controls have accessible names', () => {
 for (const id of ['btnMore', 'btnShortcuts', 'btnDownloadAs']) {
  const tag = html.match(new RegExp(`<button[^>]*id="${id}"[^>]*>`));
  assert.ok(tag, id);
  assert.match(tag[0], /aria-label="/, `#${id} is icon-only and needs a name`);
 }
});

test('the hidden describedby host exists, because a title alone reaches nobody (§7.1)', () => {
 assert.match(html, /id="whyNotes"[^>]*class="visually-hidden"/);
});

// --- contrast (§9.6) ---------------------------------------------------------
//
// Asserted arithmetically over the token pairs the stylesheet actually uses, in
// both themes. What this does NOT catch is stated in the contract as residual
// §18.9: a token used against a background it was never paired with. Structural,
// not perceptual — the NVDA and eyes-on passes are on the hardware checklist.
const css = readFileSync(new URL('./static/app.css', import.meta.url), 'utf8');
function tokensOf(pattern) {
 const block = css.match(pattern);
 assert.ok(block, `missing token block ${pattern}`);
 const out = {};
 for (const m of block[1].matchAll(/--([a-z-]+):\s*(#[0-9a-fA-F]{3,8})/g)) out[m[1]] = m[2];
 return out;
}
function luminance(hex) {
 let h = hex.replace('#', '');
 if (h.length === 3) h = [...h].map(c => c + c).join('');
 const [r, g, b] = [0, 2, 4].map(i => parseInt(h.slice(i, i + 2), 16) / 255)
  .map(c => c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
 return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function ratio(a, b) {
 const [x, y] = [luminance(a), luminance(b)];
 return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

test('every foreground/background token pair clears 4.5:1 in both themes', () => {
 const light = tokensOf(/:root \{([^}]*)\}/);
 const dark = {...light, ...tokensOf(/:root\[data-theme="dark"\] \{([^}]*)\}/)};
 const pairs = [
  ['ink', 'surface'], ['ink', 'panel'], ['ink', 'sel-bg'],
  ['link', 'surface'], ['link', 'panel'], ['focus', 'surface'],
  ['fail', 'surface'], ['warn', 'surface'], ['ok', 'surface'], ['protected', 'surface'],
 ];
 for (const [theme, tokens] of [['light', light], ['dark', dark]]) {
  for (const [fg, bg] of pairs) {
   assert.ok(tokens[fg], `${theme}: --${fg} is not defined`);
   assert.ok(tokens[bg], `${theme}: --${bg} is not defined`);
   const got = ratio(tokens[fg], tokens[bg]);
   assert.ok(got >= 4.5, `${theme}: --${fg} on --${bg} is ${got.toFixed(2)}:1`);
  }
 }
});

test('the dark theme redefines every token the light one declares', () => {
 const light = Object.keys(tokensOf(/:root \{([^}]*)\}/));
 const dark = Object.keys(tokensOf(/:root\[data-theme="dark"\] \{([^}]*)\}/));
 const media = Object.keys(tokensOf(/@media\(prefers-color-scheme:dark\) \{ :root:not\(\[data-theme="light"\]\) \{([^}]*)\}/));
 // The two dark blocks must agree, or the toggle and the system setting
 // disagree about what dark means.
 assert.deepEqual(dark.sort(), media.sort());
 for (const token of dark) assert.ok(light.includes(token), `--${token} is dark-only`);
});

test('nothing is signalled by colour alone (§4.1)', () => {
 // Each state that has a colour also has words or a glyph beside it.
 assert.match(html, /id="bannerBreakGlass"[^>]*>\s*<span class="bannerMark"[^>]*>⚠<\/span>/, 'the warn bar carries a mark and its sentence');
 assert.match(html, /id="bannerReadonly"[^>]*>\s*<span class="bannerMark"[^>]*>🔒<\/span>/);
 assert.match(css, /\.warn-unchanged \.warnTag/, 'a permissions warning is tagged in words');
 assert.match(css, /#pDiff\.diff-special/, 'a dropped special bit differs in words as well as tone');
});
