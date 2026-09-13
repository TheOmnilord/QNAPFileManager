export const $ = selector => document.querySelector(selector);
export function el(tag, attrs = {}, text = '') {
 const node = document.createElement(tag);
 for (const [key,value] of Object.entries(attrs)) node.setAttribute(key,String(value));
 node.textContent = text;
 return node;
}
export function announce(message) { $('#announce').textContent = message; }
// toast shows a transient message with one optional action (ui-ux §4.4: a
// trashed item's Undo lives here for 15 seconds). Only one is shown at a time;
// a new one replaces the old, and dismissing cancels the timer.
// `warn` marks a toast that reports something that did NOT go as asked — a
// chmod whose setgid bit the kernel dropped, say (M3 contract §3.3). Such a
// call succeeded, so it is not an error; it is also not a success, and showing
// it in the same clothes as one would be the lie the diff exists to prevent.
let toastTimer = null;
export function toast(message, actionLabel, onAction, ms = 15000, {warn = false} = {}) {
 const box = $('#toast'); if (!box) return;
 if (toastTimer) { clearTimeout(toastTimer); toastTimer = null; }
 const hide = () => { if (toastTimer) { clearTimeout(toastTimer); toastTimer = null; } box.hidden = true; box.replaceChildren(); box.classList.remove('warn'); };
 box.classList.toggle('warn', !!warn);
 box.replaceChildren(el('span', {}, message));
 if (actionLabel && onAction) {
  const button = el('button', {class:'toastAction'}, actionLabel);
  button.addEventListener('click', () => { hide(); onAction(); });
  box.append(button);
 }
 const dismiss = el('button', {class:'toastClose','aria-label':'Dismiss'}, '×');
 dismiss.addEventListener('click', hide);
 box.append(dismiss);
 box.hidden = false;
 announce(message);
 toastTimer = setTimeout(hide, ms);
}
export function error(err) { $('#status').textContent = err.message || String(err); announce(err.message || String(err)); }
// openDialog remembers the control that opened the dialog so focus can go back
// to it when the dialog closes (M4 contract §9.2). A keyboard user who pressed
// F9 on a row must land back on that row, not at the top of the document.
const dialogOpeners = new WeakMap();
export function openDialog(id) {
 const dialog = $(id);
 if (!dialog || dialog.open) return;
 dialogOpeners.set(dialog, document.activeElement || null);
 dialog.showModal();
}
// restoreFocus is spent on the dialog's `close` event — the one place every way
// of closing arrives (Escape, the Close button, a session change closing them
// all). It is a no-op when the opener has since left the document.
export function restoreFocus(dialog) {
 const opener = dialogOpeners.get(dialog);
 dialogOpeners.delete(dialog);
 opener?.focus?.();
}
// applyWhy puts one whyDisabled verdict on one control, in all four spellings
// the contract asks for (§7.1): `disabled`, `aria-disabled`, `title`, and an
// `aria-describedby` pointing at a visually hidden node holding the same
// sentence — a `title` alone reaches neither a keyboard user nor a screen
// reader on a disabled button.
//
// `also` is a second, control-specific reason to disable — a phrase that has
// not been typed yet, a destination that is not set, a request in flight. Pass
// it as the SENTENCE for that reason, because that sentence is then what the
// control says: describing a button disabled for the phrase with the verdict's
// "Delete" would be a control that is grey while claiming to be ready (round 1,
// finding 2). A bare `true` still disables, with a neutral line, so a caller
// cannot produce a silent grey button by accident.
export const WHY_UNAVAILABLE = 'This is not available yet.';
const whyNotes = new Map();
export function applyWhy(selector, verdict, also = false) {
 const node = $(selector);
 if (!node) return verdict;
 const blocked = also === true ? WHY_UNAVAILABLE : (typeof also === 'string' ? also.trim() : '');
 const off = !verdict.allowed || !!blocked;
 // The verdict's own refusal outranks the dialog's: read-only mode is the
 // reason nothing here can be pressed, whatever else is also unfinished.
 const sentence = !verdict.allowed ? verdict.sentence : (blocked || verdict.sentence);
 node.disabled = off;
 node.setAttribute?.('aria-disabled', String(off));
 node.title = sentence;
 const id = `why-${String(selector).replace(/^#/, '')}`;
 let note = whyNotes.get(id);
 if (!note) {
  const host = $('#whyNotes');
  if (!host) return verdict;
  note = el('span', {id, class: 'visually-hidden'});
  host.append(note);
  whyNotes.set(id, note);
 }
 // The described sentence is the one the control is actually showing, not the
 // verdict's — they differ exactly when the dialog's own reason is what disables.
 note.textContent = sentence;
 node.setAttribute?.('aria-describedby', id);
 return verdict;
}
export function pathArgs(entry) { return entry.pathB64 ? {pathB64:entry.pathB64} : {path:entry.path}; }
export function route(entry) { return entry.pathB64 ? '#b64/' + entry.pathB64 : '#' + entry.path.split('/').map(encodeURIComponent).join('/'); }
export function parseRoute(hash) {
 hash=hash.replace(/^#/,'');
 const split=hash.indexOf('?'),pathname=split<0 ? hash : hash.slice(0,split);
 // Accept existing bookmarks as well as the byte-safe #b64/<value> form.
 const pathB64=hash.startsWith('b64/') ? hash.slice(4) : split<0 ? '' : new URLSearchParams(hash.slice(split+1)).get('pathB64') || '';
 if (hash.startsWith('b64/') && !pathB64 || pathB64 && !/^[A-Za-z0-9_-]+$/.test(pathB64)) throw new Error('Invalid byte path.');
 const path=pathB64 ? bytePath(rawPath({pathB64})).path : pathname.startsWith('/') ? decodeURIComponent(pathname) : '/share';
 if (!path.startsWith('/')) throw new Error('Use an absolute path.');
 if (path.split('/').some(part => part==='.' || part==='..')) throw new Error('Path components "." and ".." are not allowed.');
 return {path,pathB64};
}
export function rawPath(entry) { return entry.pathB64 ? atob(entry.pathB64.replace(/-/g,'+').replace(/_/g,'/')) : String.fromCharCode(...new TextEncoder().encode(entry.path)); }
export function bytePath(raw) { return {path:new TextDecoder().decode(Uint8Array.from(raw,c=>c.charCodeAt(0))),pathB64:btoa(raw).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}; }
// CSSOM updates external stylesheet rules; no inline style attributes or blocks.
export function heightRule(selector) {
 const sheet = [...document.styleSheets].find(s => s.href && new URL(s.href).pathname.endsWith('/app.css'));
 const index = sheet.insertRule(`${selector} { height: 0px; }`,sheet.cssRules.length);
 return pixels => { sheet.cssRules[index].style.height = `${Math.max(0,pixels)}px`; };
}
