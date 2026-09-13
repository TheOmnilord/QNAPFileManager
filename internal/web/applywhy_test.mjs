// Run with: node --test internal/web/applywhy_test.mjs
//
// applyWhy is the four spellings §7.1 asks for — disabled, aria-disabled,
// title, aria-describedby — put on one control from one verdict.
//
// Round-1 finding 2: a primary button disabled for the DIALOG's own reason (a
// phrase not yet typed, a destination not yet chosen) carried the verdict's
// enabled sentence, so it was grey while describing itself as ready. The
// dialog's reason is now what such a control says, in both places.
import assert from 'node:assert/strict';
import {test} from 'node:test';

class Node {
 constructor() { this.attrs = {}; this.children = []; this.textContent = ''; this.disabled = false; this.title = ''; }
 setAttribute(k, v) { this.attrs[k] = String(v); }
 getAttribute(k) { return this.attrs[k] ?? null; }
 append(...kids) { this.children.push(...kids); }
 addEventListener() {}
}
const nodes = new Map();
const $ = sel => { if (!nodes.has(sel)) nodes.set(sel, new Node()); return nodes.get(sel); };
globalThis.document = {querySelector: $, createElement: () => new Node(), addEventListener() {}, activeElement: null};
globalThis.window = {addEventListener() {}};

const {applyWhy, WHY_UNAVAILABLE} = await import('./static/js/dom.js');

// described reads back the sentence the hidden node actually holds, through the
// id the control points at — the round trip a screen reader makes.
function described(selector) {
 const id = $(selector).getAttribute('aria-describedby');
 const note = $('#whyNotes').children.find(child => child.attrs.id === id);
 return note?.textContent ?? null;
}
const allowed = sentence => ({allowed: true, cause: '', sentence, causes: []});
const refused = sentence => ({allowed: false, cause: 'readonly', sentence, causes: ['readonly']});

test('an allowed control carries its own title in all four spellings', () => {
 applyWhy('#btnOne', allowed('Delete'));
 assert.equal($('#btnOne').disabled, false);
 assert.equal($('#btnOne').getAttribute('aria-disabled'), 'false');
 assert.equal($('#btnOne').title, 'Delete');
 assert.equal(described('#btnOne'), 'Delete');
});

test('a refused control carries the verdict’s sentence, and says so to a screen reader too', () => {
 applyWhy('#btnTwo', refused('Read-only mode is on, so nothing can be changed. An administrator can turn it off in Settings.'));
 assert.equal($('#btnTwo').disabled, true);
 assert.equal($('#btnTwo').getAttribute('aria-disabled'), 'true');
 assert.match($('#btnTwo').title, /^Read-only mode is on/);
 assert.equal(described('#btnTwo'), $('#btnTwo').title, 'the title and the description never differ');
});

test('a control disabled for the dialog’s own reason SAYS that reason (finding 2)', () => {
 applyWhy('#delOK', allowed('Delete'), 'Type “report.txt” in the box to confirm.');
 assert.equal($('#delOK').disabled, true);
 assert.equal($('#delOK').getAttribute('aria-disabled'), 'true');
 assert.equal($('#delOK').title, 'Type “report.txt” in the box to confirm.');
 assert.equal(described('#delOK'), 'Type “report.txt” in the box to confirm.');
 assert.notEqual($('#delOK').title, 'Delete', 'a grey button must not claim to be ready');
});

test('the verdict’s refusal outranks the dialog’s reason', () => {
 applyWhy('#delOK', refused('Read-only mode is on, so nothing can be changed. An administrator can turn it off in Settings.'), 'Type the phrase to confirm.');
 assert.equal($('#delOK').disabled, true);
 assert.match($('#delOK').title, /^Read-only mode is on/, 'read-only is why nothing here can be pressed');
 assert.equal(described('#delOK'), $('#delOK').title);
});

test('clearing the dialog’s reason returns the control to its own sentence', () => {
 applyWhy('#xferOK', allowed('Copy to another folder (Ctrl+C, then Ctrl+V)'), 'Choose a destination folder first.');
 assert.equal($('#xferOK').disabled, true);
 applyWhy('#xferOK', allowed('Copy to another folder (Ctrl+C, then Ctrl+V)'), '');
 assert.equal($('#xferOK').disabled, false);
 assert.equal($('#xferOK').title, 'Copy to another folder (Ctrl+C, then Ctrl+V)');
 assert.equal(described('#xferOK'), $('#xferOK').title);
});

test('a bare true still disables, and still says something', () => {
 applyWhy('#pApply', allowed('Permissions (F9)'), true);
 assert.equal($('#pApply').disabled, true);
 assert.equal($('#pApply').title, WHY_UNAVAILABLE);
 assert.equal(described('#pApply'), WHY_UNAVAILABLE, 'no control is ever grey in silence');
 // Whitespace is not a reason.
 applyWhy('#pApply', allowed('Permissions (F9)'), '   ');
 assert.equal($('#pApply').disabled, false);
});

test('one control, one hidden node, reused across repaints', () => {
 const before = $('#whyNotes').children.length;
 applyWhy('#btnOne', allowed('Delete'));
 applyWhy('#btnOne', allowed('Delete'));
 applyWhy('#btnOne', refused('No.'));
 assert.equal($('#whyNotes').children.length, before, 'repainting must not grow the document');
 assert.equal(described('#btnOne'), 'No.');
});
