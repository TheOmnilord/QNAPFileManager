// keys.js is the keyboard map and the document-level handler's binding table,
// in one file, because M4 contract §9.4 makes the map in #dlgShortcuts
// authoritative: a shortcut must not be addable, removable or re-bindable
// without the dialog changing.
//
// Three things live here and are cross-checked against each other by
// internal/web/keys_test.mjs:
//
//   KEYMAP        — the rows of the dialog's table, in display order.
//   appBindings() — the REAL table app.js dispatches on. Its chords must be
//                   exactly the KEYMAP rows whose scope is 'app'.
//   the list      — list.js owns the rows whose scope is 'list'; the test reads
//                   its switch and asserts the cases and the rows agree, the
//                   same shape as the Go element-id and route contract tests.
//
// Nothing here touches the DOM: appBindings takes its collaborators as
// arguments, so the whole table can be built in node and inspected.

// chordOf normalises a keyboard event to one string.
//
// Ctrl and Meta are the same chord (a Mac user's Cmd+C is a copy).
//
// Shift is part of the chord whenever a modifier is held, and otherwise only
// for keys that do not already encode it: '?' is the shifted '/', and spelling
// it 'Shift+?' would describe the same press twice — but Ctrl+Shift+V is NOT
// Ctrl+V. Dropping Shift for printable keys made the browser's own
// Ctrl+Shift+V (paste without formatting), Ctrl+Shift+C (DevTools' inspector)
// and Ctrl+Shift+X fire this app's clipboard bindings instead (round 2,
// finding 1). Shift+Delete stays unbound, as the map documents.
export function chordOf(event) {
 const key = String(event?.key ?? '');
 if (!key) return '';
 const printable = key.length === 1;
 const modified = !!(event.ctrlKey || event.metaKey || event.altKey);
 const parts = [];
 if (event.ctrlKey || event.metaKey) parts.push('Ctrl');
 if (event.altKey) parts.push('Alt');
 if (event.shiftKey && (!printable || modified)) parts.push('Shift');
 parts.push(printable && /[a-z]/i.test(key) ? key.toUpperCase() : key);
 return parts.join('+');
}

// LISTING_CHORDS act on the LISTING's selection. While the search results cover
// the listing they do nothing at all and say so once: the selection they would
// act on is invisible (round 1, finding 1).
export const LISTING_CHORDS = new Set(['Delete', 'Ctrl+C', 'Ctrl+X', 'Ctrl+V']);
export const LISTING_PAUSED_MESSAGE = 'Close the search results (Esc) to act on this folder.';

// KEYMAP is the dialog's table. `keys` is what the table prints, `chord` is what
// chordOf produces for an app-scope row, `cases` are the switch cases a
// list-scope row is implemented by, and a row with neither is a note about a
// modifier or about typing — real behaviour with no case of its own.
export const KEYMAP = [
 {scope: 'list', keys: '↑ ↓', what: 'Move the focused row', cases: ['ArrowUp', 'ArrowDown']},
 {scope: 'list', keys: 'Home / End', what: 'First or last row', cases: ['Home', 'End']},
 {scope: 'list', keys: 'Page Up / Page Down', what: 'Move a screen at a time', cases: ['PageUp', 'PageDown']},
 {scope: 'list', keys: 'Shift + movement', what: 'Extend the selection', cases: []},
 {scope: 'list', keys: 'Ctrl + movement', what: 'Move without changing the selection', cases: []},
 {scope: 'list', keys: 'Space', what: 'Select or deselect the focused row', cases: [' ']},
 {scope: 'list', keys: 'Ctrl+A', what: 'Select everything in this folder', cases: ['a', 'A']},
 {scope: 'list', keys: 'Enter', what: 'Open the folder or file', cases: ['Enter']},
 {scope: 'list', keys: 'Alt+Enter', what: 'Properties', cases: ['Enter']},
 {scope: 'list', keys: 'F4', what: 'View the file as text', cases: ['F4']},
 {scope: 'list', keys: 'Shift+F10 / Menu', what: 'Actions for the focused row', cases: ['F10', 'ContextMenu']},
 {scope: 'list', keys: 'Esc', what: 'Clear the selection', cases: ['Escape']},
 {scope: 'list', keys: 'Type a name', what: 'Jump to the first loaded match', cases: []},
 {scope: 'app', keys: 'Delete', what: 'Move the selection to Trash', chord: 'Delete'},
 {scope: 'app', keys: 'F9', what: 'Permissions', chord: 'F9'},
 {scope: 'app', keys: 'Ctrl+C', what: 'Mark the selection to copy', chord: 'Ctrl+C'},
 {scope: 'app', keys: 'Ctrl+X', what: 'Mark the selection to move', chord: 'Ctrl+X'},
 {scope: 'app', keys: 'Ctrl+V', what: 'Paste into this folder', chord: 'Ctrl+V'},
 {scope: 'app', keys: 'Ctrl+F', what: 'Search this folder and below', chord: 'Ctrl+F'},
 {scope: 'app', keys: 'Ctrl+L', what: 'Edit the path', chord: 'Ctrl+L'},
 {scope: 'app', keys: '/', what: 'Filter the names loaded so far', chord: '/'},
 {scope: 'app', keys: 'Ctrl+H', what: 'Show or hide hidden items', chord: 'Ctrl+H'},
 {scope: 'app', keys: 'Backspace', what: 'Go to the parent folder', chord: 'Backspace'},
 {scope: 'app', keys: 'Alt+←', what: 'Back', chord: 'Alt+ArrowLeft'},
 {scope: 'app', keys: 'Alt+→', what: 'Forward', chord: 'Alt+ArrowRight'},
 {scope: 'app', keys: 'F5', what: 'Refresh this folder', chord: 'F5'},
 {scope: 'app', keys: 'Esc', what: 'Close the results, the actions menu or the folder drawer', chord: 'Escape'},
 {scope: 'app', keys: '?', what: 'Open this keyboard map', chord: '?'},
 {scope: 'note', keys: 'Ctrl+R', what: 'Reload the page — always the browser’s own, never intercepted'},
];

// WHERE is the third column: which surface a row applies to.
export const WHERE = {list: 'File list', app: 'Anywhere', note: 'Browser'};

// keymapRows is what the dialog's table prints, and what the test compares the
// embedded HTML against, field for field.
export function keymapRows() {
 return KEYMAP.map(row => ({keys: row.keys, what: row.what, where: WHERE[row.scope]}));
}

// appBindings is the document-level handler's table. deps are app.js's own
// collaborators; every run() owns its own preventDefault, because Escape
// deliberately does not swallow the key when there is no results view to close
// and Ctrl+C must fall through to the browser when text is selected.
export function appBindings(deps) {
 const {
  editPath, openSearch, openShortcuts, markClipboard, pasteHere,
  deleteSelection, openPerms, refresh, parent, back, forward, toggleHidden,
  focusFilter, escape, textSelected,
 } = deps;
 // A clipboard chord must never be taken from somewhere the user is copying
 // TEXT; the browser's own clipboard keeps the keys in that case.
 const clipboard = run => event => { if (textSelected()) return; event.preventDefault(); run(); };
 const simple = run => event => { event.preventDefault(); run(); };
 return new Map([
  // editable:true — these two work from inside the filter box as well, which is
  // exactly where a user reaches for them.
  ['Ctrl+L', {editable: true, run: simple(editPath)}],
  ['Ctrl+F', {editable: true, run: simple(openSearch)}],
  ['Ctrl+C', {run: clipboard(() => markClipboard('copy'))}],
  ['Ctrl+X', {run: clipboard(() => markClipboard('move'))}],
  ['Ctrl+V', {run: clipboard(pasteHere)}],
  ['Ctrl+H', {run: simple(toggleHidden)}],
  ['Delete', {run: simple(deleteSelection)}],
  ['F9', {run: simple(openPerms)}],
  ['F5', {run: simple(refresh)}],
  ['Backspace', {run: simple(parent)}],
  ['Alt+ArrowLeft', {run: simple(back)}],
  ['Alt+ArrowRight', {run: simple(forward)}],
  ['/', {run: simple(focusFilter)}],
  ['?', {run: simple(openShortcuts)}],
  // Escape decides for itself whether it consumed the key.
  ['Escape', {run: escape}],
 ]);
}

// dispatchKey is the whole document-level policy, in one pure-ish place: which
// presses are ignored, which are refused with a word, and which run.
//
// It returns what it did ('ignored' | 'paused' | 'ran') so the behaviour is
// testable without a browser.
export function dispatchKey(event, bindings, {dialogOpen = false, editing = false, listingMutable = true, announce = () => {}} = {}) {
 if (dialogOpen) return 'ignored';
 const chord = chordOf(event);
 const binding = bindings.get(chord);
 if (!binding) return 'ignored';
 if (editing && !binding.editable) return 'ignored';
 if (!listingMutable && LISTING_CHORDS.has(chord)) {
  event.preventDefault?.();
  announce(LISTING_PAUSED_MESSAGE);
  return 'paused';
 }
 binding.run(event);
 return 'ran';
}
