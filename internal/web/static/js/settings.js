import {api,apiURL} from './api.js';
import {$,el,error,announce} from './dom.js';
import {state,update,sessionGuard} from './state.js';
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

// initSettings wires the settings controls. confirm is injectable so the toggle
// confirmation can be unit tested without a live dialog.
export function initSettings(confirm=confirmDialog) {
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
   // Re-read the session so canWrite (and the toolbar) reflect the new state.
   const session=await api('api/session');
   if (!valid()) return;
   update({session});
   $('#setReadOnly').checked=session.readOnly;
   $('#chipReadonly').hidden=!!session.canWrite;
  } catch(err) { if (valid()) { ev.target.checked=!enabled; error(err); } }
 });
 $('#btnAuditRefresh').addEventListener('click',loadAudit);
 $('#btnAuditDownload').addEventListener('click',() => {
  // A same-origin GET download; no CSRF header is needed for a GET.
  const a=el('a',{href:apiURL('api/audit/export'),download:'audit.jsonl'});
  document.body.append(a); a.click(); a.remove();
 });
}
