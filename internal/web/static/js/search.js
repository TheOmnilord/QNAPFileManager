import {api} from './api.js';
import {$,announce,bytePath,el,error,openDialog,rawPath,route} from './dom.js';
import {state,update,subscribe,sessionGuard,sessionTransition} from './state.js';
import {isDirectory} from './badges.js';
import {actionMessage,confirmDialog,runMutation} from './actions.js';
import {awaitJob,trackJob} from './jobs.js';
import {loadList,render,revealEntry} from './list.js';
import {loadTree} from './tree.js';

// Search (M2-C, contract §3.4). A search is a JOB — it walks trees that can take
// a minute — so the dialog only submits it; the Operations panel owns the
// progress and the cancel, and the list pane switches to a results view when it
// finishes.
//
// Everything above the "--- dialog" line is pure. The request body (and with it
// the byte spelling of the root), the header sentence and the shaping of one hit
// into a row are unit-tested in internal/web/search_test.mjs.

export const KINDS=['any','file','dir'];

// rootRef is the search root as a pathRef for the wire, and it exists for the
// same reason destinationRef does in transfer.js: an <input> is a LOSSY view of
// a path. It strips CR and LF on assignment and shows U+FFFD for bytes that are
// not valid UTF-8, so a folder whose name the box cannot hold verbatim would be
// searched under a DIFFERENT — quite possibly existing — spelling.
//
// The rule is POSSESSION, not resemblance. While the field is untouched the
// dialog hands back the reference it opened with, and that reference is sent;
// editing the field gives it up for good (the input handler drops the pick),
// and the typed text is then the authority and is sent as {path}, UTF-8 by
// construction.
//
// What this must NEVER do is recover a byte reference by comparing the typed
// text to the current folder's DISPLAY. That comparison was here, and it was
// unsound in exactly the direction that matters: a current folder named
// "/share/\xff" displays as "/share/�", and a SIBLING really called "/share/�"
// displays the same. Typing the sibling — deliberately, character by character
// — matched the current folder's display and sent the current folder's bytes,
// so the search ran against a directory the user had just navigated away from
// (round 5, finding 2). Two spellings that look alike are not one folder, and
// the display is not evidence of anything.
export function rootRef(root,current) {
 const c=current||{};
 if (root==null) return c.pathB64 ? {pathB64:c.pathB64} : {path:String(c.path??'')};
 if (typeof root==='object') return root.pathB64 ? {pathB64:root.pathB64} : {path:String(root.path??'')};
 // Typed. A single trailing newline is paste debris and never part of a name;
 // spaces are legal, significant parts of a path and are never trimmed.
 return {path:String(root).replace(/\n$/,'')};
}

// revealNeedsHidden says whether following this hit requires the listing's
// hidden toggle to be turned on first.
//
// A search can be told to include hidden items; the LISTING has its own,
// separate toggle, and by default excludes them. So a hit on ".env" was found,
// shown in the results, and then — on clicking it — the folder opened without
// it and the reveal quietly found nothing, reporting that the file was "not on
// the pages loaded so far" (round 5, finding 1). It was not on any page.
//
// The server decides hidden-ness, and fsx.Entry carries its answer; `hidden` is
// omitempty, so it is only ever present as true. The leading dot is the same
// Linux convention the server applies, and covers a hit that arrives without
// the flag.
export function revealNeedsHidden(entry,stateHidden) {
 if (stateHidden) return false;
 const e=entry||{};
 return e.hidden===true || String(e.name??'').startsWith('.');
}

// searchRequest is the POST body (contract §3.1). Only the flags that are ON
// are sent: the route's defaults are the off state, and an explicit false adds
// nothing but noise to the audit record. `kind` is omitted for "any" for the
// same reason.
export function searchRequest(dialog,current) {
 const d=dialog||{};
 const body={roots:[rootRef(d.root,current)],query:String(d.query??'')};
 if (d.glob) body.glob=true;
 if (d.hidden) body.hidden=true;
 if (d.crossMounts) body.crossMounts=true;
 if (KINDS.includes(d.kind) && d.kind!=='any') body.kind=d.kind;
 return body;
}

// searchProblem is the submit gate, in words. An empty query is a 422 on the
// server (contract §3.1) and there is no reason to spend a round trip on it; a
// relative root is a question about what the user typed, so it is answered here.
// Everything else — does the folder exist, may this user traverse it — belongs
// to the server and is never guessed at.
export function searchProblem(body) {
 if (!String(body?.query??'').trim()) return 'Type something to look for.';
 const root=body?.roots?.[0];
 if (root && !root.pathB64 && !String(root.path??'').startsWith('/')) return 'Use an absolute path, starting with /.';
 return '';
}

// resultsTitle is the results header. The count is what was RETURNED, and the
// server's detail ("first 1000 of many") is what says the rest of the truth —
// so a capped search never reads as "1,000 results", full stop.
export function resultsTitle(count,query,root,detail) {
 const n=Math.max(0,Number(count)||0);
 const head=`${n.toLocaleString()} result${n===1 ? '' : 's'} for “${String(query??'')}” in ${String(root??'')}`;
 return detail ? `${head} · ${detail}` : head;
}

// resultRow shapes one hit into the four things its row shows, plus the
// reference the click needs.
//
// The parent is computed in BYTES and handed back as a pathRef: a hit under a
// directory whose name is not valid UTF-8 must navigate to THAT directory, and
// slicing the display path would navigate to a lookalike (or to nothing). The
// root "/" has itself for a parent, which is the only sane answer.
export function resultRow(entry) {
 const e=entry||{};
 let raw='';
 try { raw=rawPath({path:String(e.path??''),pathB64:e.pathB64}); } catch { raw=String(e.path??''); }
 const cut=raw.lastIndexOf('/');
 const parentRaw=cut>0 ? raw.slice(0,cut) : '/';
 const parent=bytePath(parentRaw);
 const dir=e.type==='dir';
 return {
  name:e.name || (cut>=0 ? bytePath(raw.slice(cut+1)).path : String(e.path??'')),
  parent:parent.path,
  parentRef:parent,
  parentRaw,
  size:dir ? '—' : (Number(e.size)||0).toLocaleString(),
  modified:e.mtime ? new Date(e.mtime).toLocaleString() : '',
  dir,
 };
}

// A search is a job: it can walk for a minute, and nothing stops the user from
// starting another one meanwhile. Search A (slow) then B: B finishes first and
// is displayed, then A lands and replaced B's results with its own — the user
// was left reading answers to a question they had already moved on from, under
// B's header (round 2, finding 3). Only the LATEST search owns the results
// pane; an older one is not cancelled and not hidden — its job entry in the
// Operations panel runs and reports exactly as it always did — it simply does
// not get to redraw a view it no longer describes.
//
// "Latest" is decided by SUBMISSION order, not by the order the 202s come back.
// Ownership used to be recorded from the response — `searchJob = res.job.id` —
// and the two orders are not the same order: A's pre-flight can be slower than
// B's, so B's 202 lands first and A's lands second and quietly took the pane
// back. B then finished, was judged superseded by A, and was thrown away; the
// user's newest search was the one that never appeared (round 3).
//
// So each submission takes a ticket before it asks the server anything, and a
// 202 may only claim the pane while its ticket is still the newest one issued.

// claimResults folds one 202 into "who owns the results pane": the claim wins
// only if its submission is still the latest SUBMITTED, whenever it arrives.
export function claimResults(owner,claim,latest) {
 if (!claim || !claim.id || claim.seq !== latest) return owner;
 return {seq:claim.seq,id:claim.id};
}

// searchOutcomeWins says whether a finished search may PAINT the pane: only the
// job the owner names, and only while that is still who the owner names.
export function searchOutcomeWins(id,owner) { return !!id && owner?.id === id; }

// searchTeardown says what a session change must clear, or null when there is
// nothing to do.
//
// A search leaves THREE things behind, and the old teardown cleared one of them
// — and only when it happened to be set. So: Alice followed a hit, signed out
// while the parent folder was still loading, and Bob's listing satisfied the
// pending reveal and selected the file Alice had gone looking for; and opening
// Search showed Alice's query, her root and her flags, in Bob's session
// (round 9). The reveal survived precisely because searchResults was null by
// then and the teardown returned early.
//
// Returning the whole patch — rather than a boolean — is what makes the test
// able to pin its COMPLETENESS, which is the part that was wrong.
export function searchTeardown(before,after) {
 if (sessionTransition(before,after)==='refresh') return null;
 return {searchResults:null,searchJob:null,pendingReveal:null};
}

// resultLink is the "→ target" annotation on a result row, or null for a row
// that is not a symlink (or is one nothing can be said about).
//
// The listing RESOLVES symlinks, so there an absent linkResolved means the
// target really is missing and "(broken)" is the truth. Search does not follow
// links — that is the point of a walk that never leaves the tree it was given —
// so a hit carries linkTarget and nothing else, and the listing's renderer read
// that absence as proof of breakage: every symlink in every result set was
// struck through and labelled "→ ? (broken)", including the healthy ones
// (round 10).
//
// Not having looked is not the same as having looked and found nothing. So an
// uninspected link says where it points and makes no claim about what is there;
// and where there is not even a target to name, it says nothing at all rather
// than "?" — a question mark is a claim too, and the wrong one.
export function resultLink(entry) {
 const e=entry||{};
 if (!(e.isSymlink || e.type==='symlink')) return null;
 const target=e.linkTarget ? String(e.linkTarget) : '';
 // Any of these is evidence that something actually followed the link.
 const inspected=!!(e.linkResolved || e.linkResolvedB64 || e.targetType);
 if (!inspected) {
  return target
   ? {text:`→ ${target}`,state:'uninspected',title:'Symlink — search does not follow links, so its target was not inspected.'}
   : null;
 }
 const broken=!(e.linkResolved || e.linkResolvedB64);
 return {text:`→ ${target || '?'}${broken ? ' (broken)' : ''}`,state:broken ? 'broken' : 'ok',title:''};
}

// escapeReturnsToListing says whether Escape (or the Back button) has a results
// view to close. It is a question about STATE, not about the DOM, so it is the
// same answer for the key handler and for anything else that needs to know.
export function escapeReturnsToListing(current) {
 return !!(current?.searchResults && Array.isArray(current.searchResults.hits) && current.searchResults.open);
}

// --- dialog ------------------------------------------------------------------

// The root the dialog opened on, kept as a reference until the user edits the
// field (see rootRef). pending and generation are the same submission lock
// transfer.js uses: a search can take a minute, dismissal is never blocked, and
// a late answer must not land on a dialog that has been reopened since.
let rootPicked=null,pending=false,generation=0;
// submitted counts the search SUBMISSIONS, so a ticket taken before the request
// records the order the user asked in — which is the only order that matters,
// and is not the order the answers come back in.
let submitted=0;

const setError = message => { $('#searchError').textContent=message||''; $('#searchError').hidden=!message; };

// searchJobView fetches the finished search from the SINGLE-job endpoint, which
// is the only place a search's hits are published.
//
// GET /api/jobs — the listing the Operations panel polls twice a second, for
// every live job — deliberately does NOT carry result.hits: a thousand entries
// on every tick is not a listing, it is a firehose. So the results view asks
// for the job by id and builds itself from that answer; a view assembled from a
// polled row would quietly show "0 results" for a search that found plenty.
//
// The request is made here rather than inherited from awaitJob so the source is
// this module's own and cannot drift if the waiting helper is ever changed. The
// job awaitJob returned is the fallback for the one case that can legitimately
// fail — a job reaped between finishing and being asked about — and it came
// from the same endpoint moments earlier, so it is a fallback and not a
// compromise.
async function searchJobView(id,waited) {
 try {
  const data=await api(`api/jobs/${id}`);
  return data.job || waited;
 } catch { return waited; }
}

function dialogState() {
 return {
  query:$('#searchQuery').value,
  glob:$('#searchGlob').checked,
  hidden:$('#searchHidden').checked,
  crossMounts:!$('#searchCrossRow').hidden && $('#searchCross').checked,
  kind:$('#dlgSearch').querySelector('input[name=searchKind]:checked')?.value || 'any',
  root:rootPicked || $('#searchRoot').value,
 };
}

export function openSearch() {
 if (!state.session) return;
 generation++;
 pending=false;
 rootPicked={path:state.path,pathB64:state.pathB64};
 $('#searchRoot').value=state.path;
 // The query survives between openings: refining a search is the common case,
 // and retyping it is the annoying one.
 const hero=state.session?.family==='quts_hero';
 $('#searchCrossRow').hidden=!hero;
 if (!hero) $('#searchCross').checked=false;
 setError('');
 $('#searchOK').disabled=false;
 openDialog('#dlgSearch');
 $('#searchQuery').focus(); $('#searchQuery').select?.();
}

async function submit() {
 if (pending) return;
 const body=searchRequest(dialogState(),{path:state.path,pathB64:state.pathB64});
 const problem=searchProblem(body);
 if (problem) { setError(problem); $('#searchQuery').focus(); return; }
 const shownRoot=rootPicked ? rootPicked.path : $('#searchRoot').value;
 // The ticket is taken HERE, before anything is awaited: this is the moment the
 // user asked, and it is what orders this search against the next one.
 const ticket=++submitted;
 const valid=sessionGuard(),mine=generation;
 // live() is the dismissal story: the dialog may be abandoned while the job
 // runs, and when it is, this submission stops owning the dialog — its own or
 // the next one.
 const live = () => valid() && mine===generation && $('#dlgSearch').open;
 pending=true; $('#searchOK').disabled=true; setError('');
 try {
  const res=await runMutation('api/jobs/search',body,async confirm => {
   if (!live()) return false;
   const summary=confirm.summary||{};
   return confirmDialog({title:'Confirm search',body:confirm.message||'This search needs confirmation.',why:(summary.warnings||[]).join(' · '),okLabel:'Search'});
  });
  if (!valid()) return;
  if (res===null) return;
  // The job exists the moment the server says 202, so it is tracked even if the
  // dialog was dismissed meanwhile: an accepted search must be visible and
  // cancellable in the panel.
  // Every accepted search is tracked, whatever its ticket: the work exists on
  // the server and must be visible and cancellable in the panel.
  trackJob(res.job);
  // Ownership of the RESULTS PANE is the separate question, and it is settled
  // by the ticket rather than by having answered first.
  const owner=claimResults(state.searchJob,{seq:ticket,id:res.job.id},submitted);
  if (owner!==state.searchJob) update({searchJob:owner});
  if (live()) $('#dlgSearch').close();
  announce(`Searching ${shownRoot} for “${body.query}”…`);
  const waited=await awaitJob(res.job.id);
  if (!valid()) return;
  // Superseded while it walked: its job entry in the panel has already reported
  // for itself, and the pane belongs to the newer search. Asked BEFORE the hits
  // are fetched, so a search nobody is waiting on costs nothing more.
  if (!searchOutcomeWins(res.job.id,state.searchJob)) { announce(`The earlier search for “${body.query}” finished — see Operations.`); return; }
  if (!waited) { announce('The search is still running — see Operations.'); return; }
  if (waited.state!=='done' && waited.state!=='cancelled') { error(new Error(waited.error || waited.note || `The search ${waited.state}.`)); return; }
  const job=await searchJobView(res.job.id,waited);
  if (!valid()) return;
  // The pane can change hands during that one request, too.
  if (!searchOutcomeWins(res.job.id,state.searchJob)) { announce(`The earlier search for “${body.query}” finished — see Operations.`); return; }
  const result=job.result||{};
  const hits=Array.isArray(result.hits) ? result.hits : [];
  update({searchResults:{
   query:body.query,root:shownRoot,
   // A cancelled search reports what it managed before it stopped; saying so is
   // better than throwing away hits the user can already use.
   detail:[result.detail,job.state==='cancelled' ? 'cancelled — partial results' : ''].filter(Boolean).join(' · '),
   hits,
   // focus is the roving tabindex's position: which row owns the keyboard, and
   // which entry the single-item toolbar actions point at.
   focus:hits.length ? 0 : -1,
   open:false,
  }});
  openResultsView();
 } catch(err) {
  const message=actionMessage(err);
  if (!valid()) return;
  if (live()) setError(message); else error(new Error(message));
 } finally { if (mine===generation) { pending=false; if (live()) $('#searchOK').disabled=false; } }
}

// --- results view ------------------------------------------------------------

// The results REPLACE the listing in the same pane rather than opening yet
// another dialog: they are a view of the file system, they can be long, and the
// user has to be able to work through them. state.path is untouched, so closing
// them puts the listing back exactly as it was.

// rows are the painted result rows, kept for the roving tabindex: exactly one
// of them is in the tab order at a time, and the arrows move which.
let rows=[];
// stashed is the listing's selection while the results cover it. It is put away
// rather than thrown away — building a selection is work — but it is only given
// back if the listing has not been reloaded underneath it, because an index
// into a listing that has since changed names a different file.
let stashed=null;

function applyRoving(index) {
 rows.forEach((row,n) => {
  row.tabIndex=n===index ? 0 : -1;
  row.setAttribute('aria-selected',String(n===index));
  row.classList.toggle('selected',n===index);
 });
}

// focusResult moves the roving tabindex. The index is published to state so the
// toolbar can point Download, View text and Properties at the focused hit —
// a result row is the only thing that IS selected while the results are up.
function focusResult(index,{open=false}={}) {
 const found=state.searchResults;
 if (!found?.hits?.length) return;
 const i=Math.max(0,Math.min(found.hits.length-1,Math.floor(Number(index))||0));
 if (i!==found.focus) update({searchResults:{...found,focus:i}});
 applyRoving(i);
 rows[i]?.focus?.();
 if (open) openHit(found.hits[i]);
}

// resultNameCell is the listing's name cell minus the claims a search cannot
// make. It is not nameCell(): that one strikes an unresolved symlink through
// and calls it broken, which for a search hit is simply not known.
function resultNameCell(entry) {
 const cell=el('span',{role:'gridcell',class:'name',title:entry.path});
 const glyph=entry.isSymlink ? '🔗' : isDirectory(entry) ? '📁' : entry.type==='file' ? '📄' : '⚙';
 cell.append(el('span',{'aria-hidden':'true',class:'badge'},glyph));
 cell.append(el('span',{class:'nameText'},entry.name));
 if (entry.class==='protected') cell.append(el('span',{class:'badge',title:'Protected system path','aria-label':'Protected system path'},'🛡'));
 if (entry.mountPoint) cell.append(el('span',{class:'badge',title:'Mount point','aria-label':'Mount point'},'⏏'));
 const link=resultLink(entry);
 if (link) cell.append(el('span',{class:'target',title:link.title},link.text));
 return cell;
}

function paintResults() {
 const found=state.searchResults;
 if (!found) return;
 $('#resultsTitle').textContent=resultsTitle(found.hits.length,found.query,found.root,found.detail);
 // The same idiom the file list uses: a click focuses, a double-click (or
 // Enter) opens — except on a narrow screen, where the list opens on a single
 // tap and so does this.
 const tapOpens = () => matchMedia('(max-width:30rem)').matches;
 rows=found.hits.map((entry,i) => {
  const shaped=resultRow(entry);
  const row=el('div',{role:'row',class:'resultRow',tabindex:'-1','aria-rowindex':i+2});
  row.append(resultNameCell(entry));
  row.append(el('span',{role:'gridcell',class:'resultParent',title:shaped.parent},shaped.parent));
  row.append(el('span',{role:'gridcell'},shaped.size));
  row.append(el('span',{role:'gridcell'},shaped.modified));
  row.addEventListener('click',() => focusResult(i,{open:tapOpens()}));
  row.addEventListener('dblclick',() => openHit(entry));
  row.addEventListener('focus',() => focusResult(i));
  return row;
 });
 $('#resultsRows').replaceChildren(...rows);
 $('#results').setAttribute('aria-rowcount',String(found.hits.length+1));
 $('#resultsEmpty').hidden=found.hits.length>0;
 $('#results').hidden=false; $('#list').hidden=true;
 $('#btnResults').hidden=false;
 $('#btnResults').textContent=`Results (${found.hits.length.toLocaleString()})`;
 announce($('#resultsTitle').textContent);
 applyRoving(found.focus);
 rows[found.focus]?.focus?.();
}

// openResultsView is the one door into the results. It puts the listing's
// selection away first: every listing action is gated on the view
// (actionsEnabledFor), and a selection that counts as nothing must not still
// LOOK selected when the listing comes back mid-gesture.
function openResultsView() {
 const found=state.searchResults;
 if (!found) return;
 if (!stashed) stashed={generation:state.generation,selection:new Set(state.selection),exclude:state.exclude,focus:state.focus,anchor:state.anchor};
 update({searchResults:{...found,open:true},selection:new Set(),exclude:false});
 render();
 paintResults();
}

// showResults re-opens the last results. They are KEPT in state for the whole
// session precisely so that following a hit into its folder is not a one-way
// door: the walk is expensive and running it again to get back would be absurd.
export function showResults() {
 if (state.searchResults) openResultsView();
}

export function closeResults() {
 const found=state.searchResults;
 // Only a selection made against THIS listing can be restored; once the
 // listing has been reloaded its indices mean something else entirely.
 const restore=stashed && stashed.generation===state.generation
  ? {selection:stashed.selection,exclude:stashed.exclude,focus:stashed.focus,anchor:stashed.anchor}
  : null;
 stashed=null;
 if (found?.open) update({searchResults:{...found,open:false},...(restore||{})});
 else if (restore) update(restore);
 $('#results').hidden=true; $('#list').hidden=false;
 if (!found?.open) return;
 render();
 $('#list').focus?.();
}

// openHit follows one result to where it lives: the parent folder is opened and
// the item itself is selected there, because a hit is only useful once it is in
// its own context (its neighbours, its permissions, the actions that apply).
//
// The reveal is a REQUEST, not a promise: a folder with more than 2,000 entries
// loads lazily and the hit may be on a page nobody has fetched. state.pendingReveal
// is consumed by loadList when the listing settles, and says so when it cannot.
function openHit(entry) {
 const shaped=resultRow(entry);
 closeResults();
 // The request names the folder it is FOR and the navigation that made it, so
 // a listing that is not that folder — the user changed their mind mid-load —
 // discards it instead of selecting a namesake (round 2, finding 4).
 const want={name:entry.name,pathB64:entry.pathB64,path:entry.path,
  parent:shaped.parentRef.path,parentB64:shaped.parentRef.pathB64,generation:state.generation};
 let here='';
 try { here=rawPath({path:state.path,pathB64:state.pathB64}); } catch { here=state.path; }
 // Already in that folder: the hash would not change, no hashchange would fire
 // and the reveal would wait forever. Reveal straight away instead.
 const sameFolder=here===shaped.parentRaw;
 // A hidden hit cannot be selected in a listing that excludes hidden items, so
 // the toggle is turned on — visibly, in the checkbox, exactly as the toolbar
 // does it — and the listing is reloaded before the reveal is attempted. The
 // reveal rides along as a pendingReveal in BOTH cases, because both now end in
 // a fresh load.
 if (revealNeedsHidden(entry,state.hidden)) {
  $('#chkHidden').checked=true;
  update({hidden:true,pendingReveal:want});
  announce(`Hidden items turned on so “${want.name}” can be shown.`);
  loadTree();
  if (sameFolder) loadList(); else location.hash=route(shaped.parentRef);
  return;
 }
 if (sameFolder) { if (!revealEntry(want)) announce(`“${want.name}” is not on the loaded pages of this folder yet.`); return; }
 update({pendingReveal:want});
 location.hash=route(shaped.parentRef);
}

export function initSearch() {
 $('#btnSearch').addEventListener('click',openSearch);
 $('#btnResults').addEventListener('click',showResults);
 $('#btnResultsBack').addEventListener('click',closeResults);
 $('#searchOK').addEventListener('click',() => submit());
 // Editing the field is the ONLY thing that gives up the picked root reference.
 $('#searchRoot').addEventListener('input',() => { rootPicked=null; });
 for (const id of ['#searchQuery','#searchRoot']) {
  $(id).addEventListener('keydown',ev => { if (ev.key==='Enter' && !$('#searchOK').disabled) { ev.preventDefault(); submit(); } });
 }
 // Keyboard navigation, the same shape the file list has: one row in the tab
 // order, the arrows move it, Home/End jump, Enter opens. Without this the
 // results were reachable only with a pointer.
 $('#resultsRows').addEventListener('keydown',ev => {
  const found=state.searchResults;
  if (!found?.open || !found.hits.length) return;
  let next;
  switch (ev.key) {
  case 'ArrowDown': next=found.focus+1; break;
  case 'ArrowUp': next=found.focus-1; break;
  case 'Home': next=0; break;
  case 'End': next=found.hits.length-1; break;
  case 'PageDown': next=found.focus+10; break;
  case 'PageUp': next=found.focus-10; break;
  case 'Enter': case ' ': ev.preventDefault(); openHit(found.hits[found.focus]); return;
  default: return;
  }
  ev.preventDefault();
  focusResult(next);
 });
 $('#results').addEventListener('keydown',ev => { if (ev.key==='Escape') { ev.preventDefault(); closeResults(); } });
 // A search belongs to a session and to nothing else: one user's hits, one
 // user's pending reveal and one user's typed query must never still be there
 // for the next. The transition is classified rather than testing for a null
 // session, so a switch is caught however it arrives, and the clearing is
 // unconditional — the bug was an early return when there happened to be no
 // results, which left the reveal and the form behind.
 //
 // Assigned rather than update()d: nothing renders from these, and notifying
 // from inside a notification is a re-entrancy nobody needs (the same rule
 // transfer.js applies to the clipboard).
 let lastSession=state.session;
 subscribe(() => {
  const before=lastSession;
  lastSession=state.session;
  const patch=searchTeardown(before,state.session);
  if (!patch) return;
  Object.assign(state,patch);
  stashed=null; rows=[]; rootPicked=null; pending=false;
  $('#results').hidden=true; $('#list').hidden=false; $('#btnResults').hidden=true;
  $('#resultsRows').replaceChildren();
  // The form too: a query is as much the previous user's as the hits are.
  $('#searchQuery').value=''; $('#searchRoot').value='';
  $('#searchGlob').checked=false; $('#searchHidden').checked=false; $('#searchCross').checked=false;
  for (const radio of $('#dlgSearch').querySelectorAll('input[name=searchKind]')) radio.checked=radio.value==='any';
  setError('');
 });
}
