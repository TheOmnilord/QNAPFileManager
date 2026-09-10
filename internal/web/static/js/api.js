import {state,update,sessionGuard} from './state.js';
import {$,announce} from './dom.js';
export function connectionNotice(title,message) {
 $('#signin').hidden = false;
 $('#signin h2').textContent = title;
 $('#signin p').textContent = message;
 announce(message);
}
export function signInNotice() {
 update({session:null,pages:new Map(),selection:new Set(),total:0,exclude:false,generation:state.generation+1});
 $('#signin').hidden = false;
 $('#listRows').replaceChildren(); $('#tree').replaceChildren();
 for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
 $('#viewerContent').textContent = ''; $('#propsContent').textContent = '';
 $('#viewerTitle').textContent = ''; $('#viewerNote').textContent = '';
 $('#identity').textContent = ''; $('#sessionDetails').textContent = '';
 $('#pathNotice').textContent = ''; $('#pathNotice').hidden = true;
 $('#mountLinks').replaceChildren(); $('#mountGroup').hidden = true;
 $('#ctxMenu').replaceChildren(); $('#ctxMenu').hidden = true;
 connectionNotice('Sign in to QTS to continue','Your session has ended. Sign in on the QTS desktop, then retry here.');
}
// The server injects the absolute base ("/qnapfilemanager/" behind the QTS
// proxy, "/" otherwise): the QTS desktop opens the app at the bare proxy path,
// so a relative "api/..." would resolve outside the proxy and hit QTS's 404.
const base = (typeof document !== 'undefined' && document.querySelector('meta[name="qfm-base"]')?.content) || '';
export function apiURL(endpoint,params={}) { return base + endpoint + (Object.keys(params).length ? '?' + new URLSearchParams(params) : ''); }
export async function api(endpoint,params={},options={}) {
 const valid=sessionGuard();
 const headers = new Headers(options.headers);
 if (state.session?.csrf) headers.set('X-QFM-CSRF',state.session.csrf);
 let response;
 try { response = await fetch(apiURL(endpoint,params),{...options,headers,credentials:'same-origin',cache:'no-store'}); }
 catch { throw Object.assign(new Error('Cannot reach the QNAPFileManager service — is it still running?'),{network:true}); }
 if (response.status === 401 && valid()) signInNotice();
 const failure={status:response.status,retryAfter:response.headers.get('Retry-After')};
 let data;
 try { data = await response.json(); }
 catch {
  // Proxies may return HTML for timeouts or overloads; preserve the status.
  throw Object.assign(new Error(`Request failed (${response.status})`),failure,{network:response.ok});
 }
 if (response.status===503 && data?.error?.code==='qts_unavailable' && state.session && valid()) {
  connectionNotice('QTS temporarily unavailable','Your session is being kept while QTS reconnects. Please retry shortly.');
 }
 if (!response.ok) throw Object.assign(new Error([data?.error?.message,data?.error?.path].filter(Boolean).join(' — ') || `Request failed (${response.status})`),failure,{
  code:data?.error?.code,confirm:data?.confirm,transient:response.status===503 && data?.error?.code==='qts_unavailable'
 });
 return data;
}
