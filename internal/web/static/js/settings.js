import {api,apiURL} from './api.js';
import {$,el,error,announce} from './dom.js';
import {state,sessionGuard} from './state.js';
import {confirmDialog} from './actions.js';

function fmtTime(t) { try { return new Date(t).toLocaleString(); } catch { return String(t); } }

function renderAudit(events) {
 const rows=(events||[]).slice().reverse().map(e => {
  const tr=el('tr');
  tr.append(
   el('td',{},fmtTime(e.t)),
   el('td',{},`${e.actor || ''}${e.root ? ' (root)' : ''}`),
   el('td',{},e.op || ''),
   el('td',{},e.path || e.pathB64 || ''),
   el('td',{},`${e.result || ''}${e.code ? ' · '+e.code : ''}`));
  return tr;
 });
 $('#auditRows').replaceChildren(...rows);
}

// loadAudit fills the settings audit table with the recent events. Admin only;
// a non-admin never opens this section.
export async function loadAudit() {
 if (!state.session?.admin) return;
 const valid=sessionGuard();
 try {
  const events=await api('api/audit',{n:200});
  if (!valid()) return;
  renderAudit(events);
 } catch(err) { if (valid()) error(err); }
}

// readOnlyConfirmText is the deliberate-action prompt shown before a read-only
// change is sent. Turning read-only OFF is the moment writes become possible on a
// root daemon; decision 7 called for a password challenge there, but the
// QTS-session identity model has no app password to challenge, so a required
// client confirmation stands in its place (decision 7 deviation, adv 9). Exported
// for the unit test.
export function readOnlyConfirmText(enabled) {
 return enabled
  ? {title:'Turn on read-only mode',body:'New changes will be blocked until you turn read-only mode off again.'}
  : {title:'Turn off read-only mode',body:'This allows changes across the whole filesystem, including protected system paths. Continue?',danger:true};
}

// initSettings wires the settings controls. `confirm` is injectable so the
// toggle confirmation can be unit tested without a live dialog.
//
// `showSession` is INJECTED rather than imported, for two reasons. app.js is the
// entry module — importing it back would close a cycle that runs the whole app
// inside a unit test — and the toggle is the one place the whole session-install
// path has to run: installing the refreshed session with update({session}) alone
// left "Read-only mode — no changes can be made" on screen after read-only had
// been turned off, because paintBanners never ran (Astra r1 #11). It has no
// default on purpose: a wiring left out fails loudly on the first toggle rather
// than quietly repainting nothing.
export function initSettings(confirm=confirmDialog,showSession) {
 $('#setReadOnly').addEventListener('change',async ev => {
  const enabled=ev.target.checked;
  // Require a deliberate confirmation before the toggle is sent (decision 7
  // deviation). Declining reverts the checkbox and sends nothing.
  if (!await confirm(readOnlyConfirmText(enabled))) { ev.target.checked=!enabled; return; }
  const valid=sessionGuard();
  try {
   await api('api/settings',{},{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({readOnly:enabled})});
   if (!valid()) return;
   announce(enabled ? 'Read-only mode is on.' : 'Read-only mode is off. Changes are now possible.');
   // Re-read the session so canWrite (and the toolbar) reflect the new state,
   // and install it the ONE way a session is ever installed: showSession paints
   // the banners, the chip, the identity line and the toolbar together, so the
   // bar and the state it describes cannot disagree.
   const session=await api('api/session');
   if (!valid()) return;
   showSession(session);
  } catch(err) { if (valid()) { ev.target.checked=!enabled; error(err); } }
 });
 $('#btnAuditRefresh').addEventListener('click',loadAudit);
 $('#btnAuditDownload').addEventListener('click',() => {
  // A same-origin GET download; no CSRF header is needed for a GET.
  const a=el('a',{href:apiURL('api/audit/export'),download:'audit.jsonl'});
  document.body.append(a); a.click(); a.remove();
 });
}
