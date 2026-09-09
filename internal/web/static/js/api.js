import {state,update} from './state.js';
import {$,announce} from './dom.js';
export function signInNotice() {
 update({session:null,pages:new Map(),selection:new Set(),total:0,exclude:false,generation:state.generation+1});
 $('#signin').hidden = false;
 $('#listRows').replaceChildren(); $('#tree').replaceChildren();
 for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
 $('#viewerContent').textContent = ''; $('#propsContent').textContent = '';
 announce('Your session has ended. Sign in on the QTS desktop, then retry here.');
}
export function apiURL(endpoint,params={}) { return endpoint + (Object.keys(params).length ? '?' + new URLSearchParams(params) : ''); }
export async function api(endpoint,params={},options={}) {
 const headers = new Headers(options.headers);
 if (state.session?.csrf) headers.set('X-QFM-CSRF',state.session.csrf);
 let response;
 try { response = await fetch(apiURL(endpoint,params),{...options,headers,credentials:'same-origin',cache:'no-store'}); }
 catch { throw new Error('Cannot reach the QNAPFileManager service — is it still running?'); }
 if (response.status === 401) signInNotice();
 const data = await response.json();
 if (!response.ok) throw new Error([data.error?.message,data.error?.path].filter(Boolean).join(' — ') || `Request failed (${response.status})`);
 return data;
}
