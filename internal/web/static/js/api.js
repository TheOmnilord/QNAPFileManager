import {state,update,sessionGuard} from './state.js';
import {$,announce} from './dom.js';
import {signInView,showLocalSignIn,hideLocalSignIn,localNotice} from './breakglass.js';
// atThisDoor is which sign-in the CURRENT listener calls for when there is no
// session. One classifier, asked by both notices, so the two cannot disagree
// about which door this page is standing at.
const atThisDoor = () => signInView({authenticated:false,listener:state.listener});
export function connectionNotice(title,message) {
 // At the emergency door a connection failure belongs under the password field.
 // The QTS panel is not merely unhelpful there — it names a remedy (the QTS
 // desktop) that may be the very thing the operator came here to repair.
 if (!state.session && atThisDoor()==='local') { showLocalSignIn(); localNotice(message); return; }
 $('#signin').hidden = false;
 $('#signin h2').textContent = title;
 $('#signin p').textContent = message;
 announce(message);
}
export function signInNotice() {
 update({session:null,pages:new Map(),selection:new Set(),total:0,exclude:false,generation:state.generation+1});
 // Which door this page is standing at was answered by the server the last time
 // /api/session was read, and it does not change under a running page. On the
 // emergency listener the QTS notice is the one thing that must NEVER appear:
 // "sign in on the QTS desktop" is the instruction nobody there can follow.
 $('#signin').hidden = atThisDoor()==='local';
 $('#listRows').replaceChildren(); $('#tree').replaceChildren();
 for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
 $('#viewerContent').textContent = ''; $('#propsContent').textContent = '';
 $('#viewerTitle').textContent = ''; $('#viewerNote').textContent = '';
 $('#identity').textContent = ''; $('#sessionDetails').textContent = '';
 $('#pathNotice').textContent = ''; $('#pathNotice').hidden = true;
 // The two persistent bars describe a SESSION; with no session they describe
 // nothing (M4 contract §8.3/§8.4). showSession paints them again on the way in.
 $('#bannerReadonly').hidden = true; $('#bannerBreakGlass').hidden = true;
 $('#mountLinks').replaceChildren(); $('#mountGroup').hidden = true;
 $('#ctxMenu').replaceChildren(); $('#ctxMenu').hidden = true;
 if (atThisDoor()==='local') { showLocalSignIn(); return; }
 hideLocalSignIn();
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
 // An answer with NO BODY is not a failure. The break-glass login route replies
 // 204 and nothing else — the session arrives as a cookie — and response.json()
 // on an empty body throws, so a CORRECT emergency password was reported as
 // "Request failed (204)" and onSignedIn was never reached (Astra r1 #1). The
 // rule is therefore: 204, or any 2xx whose body is empty, is `null`; a body
 // that is there is parsed as before, and a non-2xx with nothing to quote still
 // fails with its status.
 let data=null,body='';
 if (response.status!==204 && response.headers.get('Content-Length')!=='0') {
  try { body = await response.text(); }
  // A connection that dies mid-body is the network failure it looks like.
  catch { throw Object.assign(new Error(`Request failed (${response.status})`),failure,{network:true}); }
 }
 if (body.trim()) {
  try { data = JSON.parse(body); }
  catch {
   // Proxies may return HTML for timeouts or overloads; preserve the status.
   throw Object.assign(new Error(`Request failed (${response.status})`),failure,{network:response.ok});
  }
 } else if (!response.ok) throw Object.assign(new Error(`Request failed (${response.status})`),failure,{network:false});
 if (response.status===503 && data?.error?.code==='qts_unavailable' && state.session && valid()) {
  connectionNotice('QTS temporarily unavailable','Your session is being kept while QTS reconnects. Please retry shortly.');
 }
 if (!response.ok) throw Object.assign(new Error([data?.error?.message,data?.error?.path].filter(Boolean).join(' — ') || `Request failed (${response.status})`),failure,{
  code:data?.error?.code,confirm:data?.confirm,transient:response.status===503 && data?.error?.code==='qts_unavailable',
  blockers:data?.blockers,truncated:data?.truncated
 });
 return data;
}
