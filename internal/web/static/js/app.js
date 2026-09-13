import {$,announce,el,error,openDialog,route,parseRoute,rawPath,bytePath} from './dom.js';
import {api,signInNotice,connectionNotice} from './api.js';
import {state,update,sessionGuard,listingActions,sessionTransition} from './state.js';
import {initList,loadList} from './list.js';
import {loadTree} from './tree.js';
import {initViewer} from './viewer.js';
import {initActions,deleteSelection} from './actions.js';
import {initTransfer,markClipboard,pasteHere} from './transfer.js';
import {initUpload} from './upload.js';
import {initSearch,openSearch,closeResults,escapeReturnsToListing} from './search.js';
import {initJobs,pollJobs} from './jobs.js';
import {initTrash} from './trash.js';
import {initSettings,loadAudit} from './settings.js';
import {sessionBootstrap,transientAuthError} from './bootstrap.js';

const bootstrap=sessionBootstrap(location.href,url => history.replaceState(history.state,'',url),
 params => api('api/session',params,{signal:AbortSignal.timeout(15000)}));
let connecting=false;

function theme(value) {
 if (!['auto','light','dark'].includes(value)) value='auto';
 if (value==='auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme=value;
 $('#theme').value=value;
 try { localStorage.setItem('qfm-theme',value); } catch { /* QTS/private storage can be unavailable. */ }
}
try { theme(localStorage.getItem('qfm-theme') || 'auto'); } catch { theme('auto'); }
$('#theme').addEventListener('change',ev => theme(ev.target.value));

function navigate() {
 let path='/share',pathB64='';
 try {
  ({path,pathB64}=parseRoute(location.hash));
 } catch(err) { error(err); return; }
 update({path,pathB64}); $('#pathEdit').value=path;
 const crumbs=$('#crumbs'); crumbs.replaceChildren(el('a',{href:'#/'},'/'));
 const parts=rawPath(state).split('/').filter(Boolean);
 parts.forEach((part,i) => { const entry=bytePath('/'+parts.slice(0,i+1).join('/')); crumbs.append(el('span',{'aria-hidden':'true'},'›'),el('a',{href:route(entry)},bytePath(part).path)); });
 // Navigating shows a FOLDER, so the results view stops being what the pane is
 // for. The hits themselves survive in state.searchResults — following one into
 // its folder must not throw the search away — and the Results button brings
 // them back.
 closeResults();
 if (state.session) loadList();
}

async function connect() {
 if (connecting) return;
 connecting=true;
 const valid=sessionGuard();
 try {
  const session=await bootstrap(valid);
  if (!valid() || !session) return;
  if (!session.authenticated) { signInNotice(); return; }
  showSession(session);
 } catch(err) {
  if (valid()) {
   connectionNotice(transientAuthError(err) ? 'Connection temporarily unavailable' : 'Unable to connect',err.message);
   error(err);
  }
 } finally { connecting=false; }
}
// showSession installs a session. It is exported so the session-change path can
// be exercised directly; nothing imports app.js, which is the entry module.
export function showSession(session) {
  // A REFRESH is not a sign-in. The minute poll republishes the session
  // whenever anything in it differs — a read-only toggle made in another tab,
  // for instance — and routing that through signInNotice() published a
  // transient `session:null` first. Subscribers are notified synchronously, so
  // the upload teardown aborted the transfer and emptied the queue before the
  // refreshed session was installed a line later (round 7). Only a genuine
  // sign-out or a change of USER tears anything down.
  if (sessionTransition(state.session,session)==='switch') signInNotice();
  update({session}); $('#signin').hidden=true;
  $('#identity').textContent=`${session.user} · ${session.admin ? 'Administrator' : 'User'}`;
  $('#sessionDetails').textContent=`${session.user} · uid ${session.uid}, gid ${session.gid} · ${session.viaQTS ? 'QTS session' : 'Pinned development identity'} · ${session.rootMode ? 'root mode' : 'normal user'} · ${session.canWrite ? 'changes enabled' : 'read-only'}${session.groupsIncomplete ? ' · Warning: groups incomplete' : ''}`;
  $('#chipReadonly').textContent='Read-only'; $('#chipReadonly').hidden=!!session.canWrite;
  $('#adminSettings').hidden=!session.admin; $('#setReadOnly').checked=session.readOnly;
  if (session.groupsIncomplete) $('#announce').textContent='Warning: supplementary groups are incomplete.';
  navigate(); loadTree(); pollJobs();
}
initList(); initViewer(); initActions(); initTransfer(); initUpload(); initSearch(); initJobs(); initTrash(); initSettings();
$('.skip').addEventListener('click',ev => { ev.preventDefault(); $('#list').focus(); });
window.addEventListener('hashchange',navigate);
$('#btnRetry').addEventListener('click',connect);
$('#btnRefresh').addEventListener('click',() => { loadList(); loadTree(); });
$('#btnBack').addEventListener('click',() => history.back()); $('#btnFwd').addEventListener('click',() => history.forward());
function up() { const raw=rawPath(state); location.hash=route(bytePath(raw.slice(0,raw.lastIndexOf('/')) || '/')); }
$('#btnUp').addEventListener('click',up);
$('#pathEdit').addEventListener('keydown',ev => { if (ev.key==='Enter') { if (!ev.target.value.startsWith('/')) { error(new Error('Use an absolute path, starting with /.')); return; } location.hash=route({path:ev.target.value}); $('#list').focus(); } });
$('#btnTree').addEventListener('click',() => { const open=$('#tree').classList.toggle('open'); $('#btnTree').setAttribute('aria-expanded',String(open)); if(open) $('#tree').querySelector('[tabindex="0"]')?.focus(); });
function hidden() { update({hidden:$('#chkHidden').checked}); loadList(); loadTree(); }
$('#chkHidden').addEventListener('change',hidden);
$('#btnSettings').addEventListener('click',() => { openDialog('#dlgSettings'); if (state.session?.admin) loadAudit(); }); $('#userMenu').addEventListener('click',() => openDialog('#dlgSession')); $('#btnShortcuts').addEventListener('click',() => openDialog('#dlgShortcuts'));
for (const button of document.querySelectorAll('[data-close]')) button.addEventListener('click',() => button.closest('dialog').close());
$('#btnLogout').addEventListener('click',async () => {
 // Start with the current CSRF token, then invalidate pending reads immediately.
 const request=api('api/logout',{}, {method:'POST'});
 signInNotice();
 const valid=sessionGuard();
 try { await request; } catch(err) { if (valid()) error(err); }
});
document.addEventListener('keydown',ev => {
 // isContentEditable as well as the form controls: a key that means "copy" must
 // never be taken from somewhere the user is typing.
 const editing=ev.target.matches('input,textarea,select') || ev.target.isContentEditable,ctrl=ev.ctrlKey || ev.metaKey;
 if (document.querySelector('dialog[open]')) return;
 if (ctrl && ev.key.toLowerCase()==='l') { ev.preventDefault(); $('#pathEdit').focus(); $('#pathEdit').select(); return; }
 // Ctrl+F is the SEARCH (ui-ux §4), not the browser's find-in-page: what the
 // user wants on a virtualised listing of a million files is a server-side
 // walk, and find-in-page could only ever search the rows currently painted.
 // Like Ctrl+L it works from inside the filter box too.
 if (ctrl && !ev.altKey && ev.key.toLowerCase()==='f') { ev.preventDefault(); openSearch(); return; }
 if (editing) return;
 // Every shortcut that acts on the LISTING's selection is gated on the listing
 // being what is on screen. While the search results cover it, Ctrl+C, Ctrl+X,
 // Ctrl+V and Delete would be operating on rows nobody can see (round 1,
 // finding 1) — so they do nothing at all, and say so once.
 if ((ev.key==='Delete' || ctrl && !ev.altKey && !ev.shiftKey && ev.key.length===1 && 'cxv'.includes(ev.key.toLowerCase()))
  && !listingActions().mutate) { ev.preventDefault(); announce('Close the search results (Esc) to act on this folder.'); return; }
 if (ctrl && !ev.altKey && !ev.shiftKey && ev.key.length===1 && 'cxv'.includes(ev.key.toLowerCase())) {
  // A text selection means the user is copying TEXT; the browser's own
  // clipboard keeps the keys in that case.
  if (window.getSelection?.()?.toString()) return;
  const key=ev.key.toLowerCase();
  ev.preventDefault();
  if (key==='v') pasteHere(); else markClipboard(key==='c' ? 'copy' : 'move');
 }
 else if (ctrl && ev.key.toLowerCase()==='h') { ev.preventDefault(); $('#chkHidden').checked=!state.hidden; hidden(); }
 else if (ev.key==='Delete') { ev.preventDefault(); deleteSelection(); }
 else if (ev.key==='F5') { ev.preventDefault(); loadList(); }
 else if (ev.key==='Backspace') { ev.preventDefault(); up(); }
 else if (ev.altKey && ev.key==='ArrowLeft') { ev.preventDefault(); history.back(); }
 else if (ev.altKey && ev.key==='ArrowRight') { ev.preventDefault(); history.forward(); }
 else if (ev.key==='/') { ev.preventDefault(); $('#searchBox').focus(); }
 else if (ev.key==='?') { ev.preventDefault(); openDialog('#dlgShortcuts'); }
 else if (ev.key==='Escape') {
  // A results view is the outermost thing Escape closes: it has REPLACED the
  // listing, so dismissing it is what "go back" means here.
  if (escapeReturnsToListing(state)) { ev.preventDefault(); closeResults(); return; }
  $('#ctxMenu').hidden=true; $('#tree').classList.remove('open'); $('#btnTree').setAttribute('aria-expanded','false');
 }
 // Ctrl+R deliberately retains the browser's normal refresh behavior.
});
// The document-level suppressor: a file dropped anywhere OUTSIDE the list pane
// must do nothing at all, because the browser's default is to navigate to it —
// which inside the QTS desktop means losing the app. The list pane is the one
// drop target (upload.js), and it stops propagation so its drops never reach
// here.
for (const event of ['dragover','drop']) document.addEventListener(event,ev => { ev.preventDefault(); ev.stopPropagation(); });
// Polling couples visible state to QTS expiry even while the user is idle.
setInterval(async () => {
 if (!state.session) return;
 const valid=sessionGuard();
 try {
  const session=await api('api/session');
  if (!valid()) return;
  if (!session.authenticated) signInNotice();
  else if (JSON.stringify(session)!==JSON.stringify(state.session)) showSession(session);
 } catch(err) { if (valid()) error(err); }
},60000);
connect();
