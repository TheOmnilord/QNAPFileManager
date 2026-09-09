import {$,el,error,openDialog,route,parseRoute,rawPath,bytePath} from './dom.js';
import {api,signInNotice} from './api.js';
import {state,update,sessionGuard} from './state.js';
import {initList,loadList} from './list.js';
import {loadTree} from './tree.js';
import {initViewer} from './viewer.js';

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
 if (state.session) loadList();
}

async function connect() {
 const valid=sessionGuard();
 try {
  const session=await api('api/session');
  if (!valid()) return;
  if (!session.authenticated) { signInNotice(); return; }
  showSession(session);
 } catch(err) { if (valid()) error(err); }
}
function showSession(session) {
  if (state.session) signInNotice();
  update({session}); $('#signin').hidden=true;
  $('#identity').textContent=`${session.user} · ${session.admin ? 'Administrator' : 'User'}`;
  $('#sessionDetails').textContent=`${session.user} · uid ${session.uid}, gid ${session.gid} · ${session.viaQTS ? 'QTS session' : 'Pinned development identity'} · root mode off${session.groupsIncomplete ? ' · Warning: groups incomplete' : ''}`;
  $('#chipReadonly').textContent='Read-only browse';
  if (session.groupsIncomplete) $('#announce').textContent='Warning: supplementary groups are incomplete.';
  navigate(); loadTree();
}
initList(); initViewer();
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
$('#btnSettings').addEventListener('click',() => openDialog('#dlgSettings')); $('#userMenu').addEventListener('click',() => openDialog('#dlgSession')); $('#btnShortcuts').addEventListener('click',() => openDialog('#dlgShortcuts'));
for (const button of document.querySelectorAll('[data-close]')) button.addEventListener('click',() => button.closest('dialog').close());
$('#btnLogout').addEventListener('click',async () => {
 // Start with the current CSRF token, then invalidate pending reads immediately.
 const request=api('api/logout',{}, {method:'POST'});
 signInNotice();
 const valid=sessionGuard();
 try { await request; } catch(err) { if (valid()) error(err); }
});
document.addEventListener('keydown',ev => {
 const editing=ev.target.matches('input,textarea,select'),ctrl=ev.ctrlKey || ev.metaKey;
 if (document.querySelector('dialog[open]')) return;
 if (ctrl && ev.key.toLowerCase()==='l') { ev.preventDefault(); $('#pathEdit').focus(); $('#pathEdit').select(); return; }
 if (editing) return;
 if (ctrl && ev.key.toLowerCase()==='h') { ev.preventDefault(); $('#chkHidden').checked=!state.hidden; hidden(); }
 else if (ev.key==='F5') { ev.preventDefault(); loadList(); }
 else if (ev.key==='Backspace') { ev.preventDefault(); up(); }
 else if (ev.altKey && ev.key==='ArrowLeft') { ev.preventDefault(); history.back(); }
 else if (ev.altKey && ev.key==='ArrowRight') { ev.preventDefault(); history.forward(); }
 else if (ev.key==='/') { ev.preventDefault(); $('#searchBox').focus(); }
 else if (ev.key==='?') { ev.preventDefault(); openDialog('#dlgShortcuts'); }
 else if (ev.key==='Escape') { $('#ctxMenu').hidden=true; $('#tree').classList.remove('open'); $('#btnTree').setAttribute('aria-expanded','false'); }
 // Ctrl+R deliberately retains the browser's normal refresh behavior.
});
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
