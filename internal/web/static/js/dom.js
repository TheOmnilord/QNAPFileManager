export const $ = selector => document.querySelector(selector);
export function el(tag, attrs = {}, text = '') {
 const node = document.createElement(tag);
 for (const [key,value] of Object.entries(attrs)) node.setAttribute(key,String(value));
 node.textContent = text;
 return node;
}
export function announce(message) { $('#announce').textContent = message; }
export function error(err) { $('#status').textContent = err.message || String(err); announce(err.message || String(err)); }
export function openDialog(id) { const dialog = $(id); if (!dialog.open) dialog.showModal(); }
export function pathArgs(entry) { return entry.pathB64 ? {pathB64:entry.pathB64} : {path:entry.path}; }
export function route(entry) { return '#' + entry.path.split('/').map(encodeURIComponent).join('/') + (entry.pathB64 ? '?pathB64=' + encodeURIComponent(entry.pathB64) : ''); }
export function rawPath(entry) { return entry.pathB64 ? atob(entry.pathB64.replace(/-/g,'+').replace(/_/g,'/')) : String.fromCharCode(...new TextEncoder().encode(entry.path)); }
export function bytePath(raw) { return {path:new TextDecoder().decode(Uint8Array.from(raw,c=>c.charCodeAt(0))),pathB64:btoa(raw).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}; }
// CSSOM updates external stylesheet rules; no inline style attributes or blocks.
export function heightRule(selector) {
 const sheet = [...document.styleSheets].find(s => s.href && new URL(s.href).pathname.endsWith('/app.css'));
 const index = sheet.insertRule(`${selector} { height: 0px; }`,sheet.cssRules.length);
 return pixels => { sheet.cssRules[index].style.height = `${Math.max(0,pixels)}px`; };
}
