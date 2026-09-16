import {$,announce,el,error,openDialog,restoreFocus,route,parseRoute,rawPath,bytePath} from './dom.js';
import {api,signInNotice,connectionNotice} from './api.js';
import {state,update,sessionGuard,listingActions,sessionTransition} from './state.js';
import {initList,loadList} from './list.js';
import {loadTree} from './tree.js';
import {initViewer} from './viewer.js';
import {initProps} from './props.js';
import {initPerms,openPermsForSelection} from './perms.js';
import {initActions,deleteSelection} from './actions.js';
import {initTransfer,markClipboard,pasteHere} from './transfer.js';
import {initUpload} from './upload.js';
import {initSearch,openSearch,closeResults,escapeReturnsToListing} from './search.js';
import {initJobs,pollJobs} from './jobs.js';
import {initTrash} from './trash.js';
import {initSettings,loadAudit} from './settings.js';
import {confirmDialog} from './actions.js';
import {sessionBootstrap,transientAuthError} from './bootstrap.js';
import {banners,bannerSignature,identityLabel} from './banners.js';
import {initBreakGlass,hideLocalSignIn,listenerOf} from './breakglass.js';
import {appBindings,dispatchKey} from './keys.js';
import {initA11y} from './a11y.js';
import {initNarrow,closeMore} from './narrow.js';

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
  // Which door this page is standing at is recorded BEFORE anything branches on
  // it: signInNotice() has no payload of its own, and on the emergency listener
  // it must show the password form rather than the QTS notice (contract §2).
  // update({listener}) does not touch `session`, so it bumps no generation.
  update({listener:listenerOf(session)});
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
  update({session,listener:listenerOf(session) || state.listener});
  $('#signin').hidden=true; hideLocalSignIn();
  $('#identity').textContent=`${session.user} · ${session.admin ? 'Administrator' : 'User'}`;
  // createsAs is the server's own answer to "who will own what I make here" —
  // empty means root, which is the break-glass case and the reason §8.4's bar
  // exists. It is stated here as well as in the bar, because this dialog is
  // where a user goes to ask exactly that question.
  const owns=session.createsAs===undefined ? '' : ` · new items owned by ${session.createsAs || 'root'}`;
  // identityLabel, not viaQTS: a break-glass session has no `kind`, so viaQTS is
  // false and this dialog used to call an emergency sign-in a "pinned
  // development identity" — the one session where being told exactly what you
  // are signed in as matters most (round 1, finding 4).
  $('#sessionDetails').textContent=`${session.user} · uid ${session.uid}, gid ${session.gid} · ${identityLabel(session)} · ${session.rootMode ? 'root mode' : 'normal user'} · ${session.canWrite ? 'changes enabled' : 'read-only'}${owns}${session.groupsIncomplete ? ' · Warning: groups incomplete' : ''}`;
  $('#chipReadonly').textContent='Read-only'; $('#chipReadonly').hidden=!!session.canWrite;
  paintBanners(session);
  $('#adminSettings').hidden=!session.admin; $('#setReadOnly').checked=session.readOnly;
  if (session.groupsIncomplete) $('#announce').textContent='Warning: supplementary groups are incomplete.';
  navigate(); loadTree(); pollJobs();
}
// paintBanners paints the two persistent bars (M4 contract §8.3, §8.4).
//
// They are STATE: on for as long as the state is on, never dismissible, and
// announced once when they CHANGE — not on every navigation, which is what
// turns a live region into noise. The signature is what "changed" means.
let lastBanners='';
export function paintBanners(session) {
 const bars=banners(session),by=new Map(bars.map(bar => [bar.id,bar]));
 const readonly=by.get('bannerReadonly');
 $('#bannerReadonly').hidden=!readonly;
 $('#bannerReadonlyText').textContent=readonly?.text || '';
 $('#bannerReadonlyTail').textContent=readonly?.tail || '';
 // The inline control is offered only to someone who could use it; a non-admin
 // is told who to ask instead of being handed a button that would 403 (§8.3).
 $('#bannerReadonlySettings').hidden=!readonly?.action;
 const breakGlass=by.get('bannerBreakGlass');
 $('#bannerBreakGlass').hidden=!breakGlass;
 $('#bannerBreakGlassText').textContent=breakGlass?.text || '';
 const signature=bannerSignature(bars);
 if (signature!==lastBanners) {
  lastBanners=signature;
  if (signature) announce(bars.map(bar => `${bar.text} ${bar.tail}`.trim()).join(' '));
 }
 return bars;
}

// initPerms runs after initActions so the context menu keeps the §3.3 order:
// Rename… and Delete first, then Permissions… — extraActions is appended to.
// Settings is handed showSession because a read-only toggle changes the SESSION,
// and a session is installed in exactly one place (Astra r1 #11) — otherwise the
// banner kept saying "no changes can be made" after changes had been re-enabled.
initList(); initViewer(); initProps(); initActions(); initPerms(); initTransfer(); initUpload(); initSearch(); initJobs(); initTrash(); initSettings(confirmDialog,showSession);
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
// Accessibility and narrow layout are wired last, over the finished document:
// the focus trap and the focus return need every dialog, and the ⋯ menu needs
// the toolbar buttons it mirrors.
initA11y({dialogs:[...document.querySelectorAll('dialog')],restoreFocus});
initNarrow();
// The emergency door's sign-in. `api` is injected rather than imported by
// breakglass.js, because api.js has to ask that module which notice to show on
// a 401 and an import cycle is not worth the convenience.
initBreakGlass({api,onSignedIn:connect});
$('#bannerReadonlySettings').addEventListener('click',() => { openDialog('#dlgSettings'); if (state.session?.admin) loadAudit(); });
$('#btnLogout').addEventListener('click',async () => {
 // Start with the current CSRF token, then invalidate pending reads immediately.
 const request=api('api/logout',{}, {method:'POST'});
 signInNotice();
 const valid=sessionGuard();
 try { await request; } catch(err) { if (valid()) error(err); }
});
// The document-level shortcuts. The TABLE is keys.js's — one place the map in
// #dlgShortcuts is cross-checked against (M4 contract §9.4) — and this is only
// its collaborators and the two gates that surround it.
//
// F9 is the permissions dialog (ui-ux §3.9). It lives here rather than in the
// list's own key handler because perms.js resolves the selection through
// list.js, and list.js importing it back would close a cycle for no gain.
//
// Ctrl+R deliberately retains the browser's normal refresh behaviour.
const shortcuts=appBindings({
 editPath:() => { $('#pathEdit').focus(); $('#pathEdit').select(); },
 // Ctrl+F is the SEARCH (ui-ux §4), not the browser's find-in-page: what the
 // user wants on a virtualised listing of a million files is a server-side
 // walk, and find-in-page could only ever search the rows currently painted.
 // Like Ctrl+L it works from inside the filter box too.
 openSearch,
 openShortcuts:() => openDialog('#dlgShortcuts'),
 markClipboard,
 pasteHere,
 deleteSelection,
 openPerms:openPermsForSelection,
 refresh:() => loadList(),
 parent:up,
 back:() => history.back(),
 forward:() => history.forward(),
 toggleHidden:() => { $('#chkHidden').checked=!state.hidden; hidden(); },
 focusFilter:() => $('#searchBox').focus(),
 textSelected:() => !!window.getSelection?.()?.toString(),
 escape:ev => {
  // A results view is the outermost thing Escape closes: it has REPLACED the
  // listing, so dismissing it is what "go back" means here.
  if (escapeReturnsToListing(state)) { ev.preventDefault(); closeResults(); return; }
  if (closeMore()) { ev.preventDefault(); $('#btnMore').focus(); return; }
  $('#ctxMenu').hidden=true; $('#tree').classList.remove('open'); $('#btnTree').setAttribute('aria-expanded','false');
 },
});
document.addEventListener('keydown',ev => {
 dispatchKey(ev,shortcuts,{
  dialogOpen:!!document.querySelector('dialog[open]'),
  // isContentEditable as well as the form controls: a key that means "copy"
  // must never be taken from somewhere the user is typing.
  editing:ev.target.matches?.('input,textarea,select') || ev.target.isContentEditable,
  // Every shortcut that acts on the LISTING's selection is gated on the listing
  // being what is on screen. While the search results cover it, Ctrl+C, Ctrl+X,
  // Ctrl+V and Delete would be operating on rows nobody can see (round 1,
  // finding 1) — so they do nothing at all, and say so once.
  listingMutable:listingActions().mutate,
  announce,
 });
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
