import {api,apiURL} from './api.js';
import {$,el,error,announce} from './dom.js';
import {state,update,sessionGuard} from './state.js';

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

export function initSettings() {
 $('#setReadOnly').addEventListener('change',async ev => {
  const enabled=ev.target.checked;
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
