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
