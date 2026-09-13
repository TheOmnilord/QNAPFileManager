import {$,announce,error,openDialog,pathArgs,rawPath,toast} from './dom.js';
import {state,update,subscribe,sessionGuard} from './state.js';
import {selectionEntries,extraActions} from './list.js';
import {renderTree} from './tree.js';
import {runMutation,confirmDialog,actionMessage} from './actions.js';
import {trackJob,formatBytes} from './jobs.js';

// Copy and move (M2-B, contract §5). One dialog serves both: the only
// differences are the words and the endpoint, so there is one code path and one
// place where the destination rules live.
//
// Everything above the "--- dialog" line is pure — no DOM — so the wording, the
// "you cannot copy a folder into itself" rule and the confirmation grade are
// unit-tested rather than eyeballed through a browser.

// A transfer's confirm summary mixes two very different kinds of sentence. The
// ROUTE writes about the operation itself — a capped measurement, an
// unknown-volume prediction, the overwrite notice, the EXDEV prediction — and
// all of those are grade L1: loud, not dangerous (contract §1.2, §1.12). The
// GUARD contributes protection reasons, which are free-form rule text and are
// grade L2, the typed phrase. The wire carries no flag saying which is which,
// so the route's own sentences are PINNED here, exactly as PERMANENT_WARNING is
// pinned for delete, and anything else in the list is taken to be a guard
// reason. These strings are a contract with internal/web/routes_transfer.go.
export const TRANSFER_NOTICES=[
 'The size could not be fully measured; the totals shown are a minimum.',
 'The sizes exceed what can be counted; the totals shown are a minimum.',
 'We could not tell whether this move crosses volumes; it may need to copy and then delete the source.',
 'Existing files may be overwritten by this operation.',
];
// CROSS_DEVICE_MARK is the invariant fragment of the EXDEV prediction, whose
// full sentence names the two folders and the size, so it cannot be pinned
// whole.
export const CROSS_DEVICE_MARK='are on different volumes, so this move copies';

// transferTitle is the dialog heading.
export function transferTitle(mode,count) {
 return `${mode==='move' ? 'Move' : 'Copy'} ${Number(count||0).toLocaleString()} item(s) to…`;
}

// clipboardToast is what Ctrl+C / Ctrl+X say. The marking is inert until a
// paste, so the toast has to say where the second half of the gesture goes.
export function clipboardToast(mode,count) {
 return `${Number(count||0).toLocaleString()} item(s) marked to ${mode==='move' ? 'move' : 'copy'} — press Ctrl+V in the destination folder`;
}

// cleanPath drops a trailing slash so "/a/" and "/a" are one path; "/" stays
// "/". It deliberately does NOT trim whitespace: a trailing space is a legal —
// and distinct — part of a Linux directory name, so "/share/photos " and
// "/share/photos" are two folders and must never be conflated.
function cleanPath(path) {
 const p=String(path??'');
 return p==='/' ? '/' : p.replace(/\/+$/,'');
}

// isInside is the path-BOUNDARY test: "/a/b" is inside "/a", "/ab" is not. A
// plain startsWith is the bug this exists to avoid.
export function isInside(path,base) {
 const p=cleanPath(path),b=cleanPath(base);
 if (!p.startsWith('/') || !b.startsWith('/')) return false;
 return b==='/' ? p!=='/' : p.startsWith(b+'/');
}

// asRef accepts either a plain path string or a {path,pathB64} reference.
const asRef = value => typeof value==='string' ? {path:value} : (value||{});

// pathBytes is a path in the only spelling two paths can honestly be compared
// in: bytes. A reference with a pathB64 carries the filesystem's own bytes
// (rawPath decodes it one character per byte); a path with none was typed, and
// a typed path is UTF-8 by construction. null means "cannot be determined",
// which callers must read as unknown — never as equal.
export function pathBytes(ref) {
 const r=asRef(ref);
 if (!r.pathB64 && typeof r.path!=='string') return null;
 if (!r.pathB64 && !r.path) return null;
 try { return rawPath(r); } catch { return null; }
}

// destinationInvalid is the OK-button gate: a destination that IS one of the
// selected items, or lies inside a selected folder, can never receive them.
//
// The comparison is made in BYTES, not in the displayed text. Two distinct
// directories "/src/\xff" and "/src/\xfe" both display as "/src/�", and
// comparing those strings declared them the same folder — the gate then
// disabled OK permanently and the byte reference never got its chance. Where
// both sides decode, the bytes decide; where only one does, the other's UTF-8
// bytes are used; where neither does, the text is all there is.
//
// When a comparison cannot be made at all, the gate ABSTAINS rather than
// refusing. It is a convenience that saves a round trip: the server re-checks
// every transfer and answers invalid_target (contract §1.11), and the engine
// proves it again on descriptors (§1.7). The authority is there, not here, so
// an unanswerable question must never be what locks the button.
//
// The one text rule that stays text: an unset or relative destination is
// invalid, because that question is about what the user typed.
export function destinationInvalid(dest,entries) {
 const d=asRef(dest);
 if (!d.pathB64 && !cleanPath(d.path??'').startsWith('/')) return true;
 const db=cleanPath(pathBytes(d)??'');
 if (!db) return false;
 for (const e of entries||[]) {
  const eb=cleanPath(pathBytes(e)??'');
  if (!eb) continue;                                // unknown: abstain
  if (db===eb) return true;                         // the item itself
  if (e?.type==='dir' && isInside(db,eb)) return true; // inside the folder being copied
 }
 return false;
}

// transferSummary turns the server's confirm summary into the two lines the
// confirmation shows: the facts (what is about to move) and why it is being
// asked. They are separate because confirmDialog renders them differently — a
// sentence and a hint — and because the split is what makes both testable.
// A capped pre-scan reports -1 (design §3); an unknown total is said by not
// claiming one.
export function transferSummary(summary) {
 const s=summary||{},files=Number(s.files),bytes=Number(s.bytes),facts=[];
 if (Number.isFinite(files) && files>=0) facts.push(`${files.toLocaleString()} item(s)`);
 if (Number.isFinite(bytes) && bytes>=0) facts.push(formatBytes(bytes));
 return {body:facts.join(', ') || 'a set of items whose total size could not be measured',why:(s.warnings||[]).join(' · ')};
}

// transferGrade is the confirmation ladder for a transfer (ui-ux §6, contract
// §1.12). Grade 1 is a plain confirm — scale, an overwrite and a cross-volume
// move are all L1. Grade 2 (type the name) is for a write the guard warned
// about: "a write under a protected path is L2 as everywhere".
export function transferGrade(summary) {
 return ((summary||{}).warnings||[]).some(w => {
  const s=String(w);
  return !TRANSFER_NOTICES.includes(s) && !s.includes(CROSS_DEVICE_MARK);
 }) ? 2 : 1;
}

// destinationRef is the destination as a pathRef for the wire. The rule is
// possession, not resemblance: while a folder is PICKED — in the tree, or
// preselected by a Ctrl+V paste — that reference IS the destination, and only
// the user editing the field gives it up (the input handler clears the pick).
//
// The comparison this used to make — "the text still equals picked.path" — was
// unsound because the text is not a faithful copy of the name. An <input>
// strips CR and LF on assignment, so a folder called "photos\n" could never
// match its own field and silently fell back to the sanitised spelling: a
// DIFFERENT, quite possibly existing, directory. The displayed path is lossy in
// the same way for a name that is not valid UTF-8 (replacement characters).
// So the field is for reading; the reference is for sending.
//
// A typed path — no pick — is UTF-8 by construction and its own authority. It
// is sent exactly as typed, untrimmed: a leading or trailing space is far more
// likely a real name on a NAS than a typo. The one thing removed is a single
// trailing newline, which is paste debris and never part of a name.
export function destinationRef(picked,typed) {
 if (picked) return picked.pathB64 ? {pathB64:picked.pathB64} : {path:picked.path};
 return {path:String(typed??'').replace(/\n$/,'')};
}

// okEnabled is the submit gate. Beyond a legal destination it requires that no
// request is already in flight: the server's pre-flight can take 30 seconds
// (the scan cap, contract §1.9), and during it every repaint — a pick, a
// keystroke — used to re-enable the button, so a second click sent a SECOND
// transfer and "Keep both" duly produced "(2)" copies of everything.
export function okEnabled({dest,entries,pending}) {
 return !pending && !destinationInvalid(dest,entries);
}

// submissionLive says whether an in-flight submission still owns the dialog:
// the dialog has not been reopened since it started (the generation) and it is
// still open at all. A pre-flight can run for 30 seconds and the user must be
// able to walk away from it — so dismissal is never blocked, and instead every
// continuation asks this first. Without it a dismissed operation still raised
// its confirmation, and a late 202 closed whatever dialog happened to be open
// by then, which could be an entirely different transfer.
export function submissionLive({started,current,open}) {
 return started===current && !!open;
}

// clipboardAfterPaste is what the clipboard should hold once a paste has been
// accepted: emptied, but ONLY when the marking this submission consumed is
// still the one on it. A paste dismissed mid-pre-flight whose 202 lands minutes
// later must not wipe a selection the user has marked since — identity of the
// object, not the mere fact that a paste finished.
export function clipboardAfterPaste(current,consumed) {
 return consumed && current===consumed ? null : current;
}

// transferErrorMessage is actionMessage with the two refusals that only mean
// something in this context. The shared table carries the copy wording; a move
// into the folder the item is already in, and a move into itself, deserve to be
// said as a move.
export function transferErrorMessage(err,mode) {
 if (mode==='move' && err?.code==='exists') return 'The item is already in that folder.';
 if (mode==='move' && err?.code==='invalid_target') return 'The destination is inside the folder being moved.';
 return actionMessage(err);
}

// --- dialog ------------------------------------------------------------------

// The dialog's session state: what this dialog is about, fixed when it opened.
// `consumedBoard` is the clipboard OBJECT a Ctrl+V is spending — the one whose
// entries are in `entries` — and it belongs here rather than being read from
// state.clipboard at submit time. Marking a selection is asynchronous (it
// fetches any unloaded pages), so a Ctrl+C started before the paste can land
// while this dialog is open; reading the clipboard later would then capture
// THAT marking and the paste's success would clear a selection it never used.
let entries=[],mode='copy',consumedBoard=null,picked=null,pending=false,generation=0;

const label = () => mode==='move' ? 'Move' : 'Copy';
// Exactly what is in the box, minus a single trailing newline (paste debris).
// Spaces are never stripped: they are legal, significant parts of a path.
const destText = () => $('#xferPath').value.replace(/\n$/,'');
// destPath is the destination the submission will actually use, for display and
// for the lexical checks: a picked folder's REAL name (which the field may only
// approximate), otherwise whatever was typed.
const destPath = () => picked ? picked.path : destText();
// destFull is the destination in BOTH spellings: the display path (for "is it
// set, is it absolute", which is a question about what the user typed) and the
// byte reference (for every comparison that has to be exact).
const destFull = () => picked ? {path:picked.path,pathB64:picked.pathB64} : {path:destText()};
const conflict = () => $('#dlgTransfer').querySelector('input[name=xferConflict]:checked')?.value || 'skip';
const crossMounts = () => !$('#xferCrossRow').hidden && $('#xferCross').checked;

function setError(message) { $('#xferError').textContent=message||''; $('#xferError').hidden=!message; }

const destRef = () => destinationRef(picked,destText());

// highlight marks the destination in the tree, and only there.
function highlight(path) {
 const want=cleanPath(path);
 for (const item of $('#xferTree').querySelectorAll('[role=treeitem]')) {
  const on=cleanPath(item.entry?.path)===want && !!want;
  item.querySelector('.treeLine').classList.toggle('picked',on);
  item.setAttribute('aria-selected',String(on));
 }
}

function paint() {
 const dest=destPath();
 $('#xferSummary').textContent=`${entries.length.toLocaleString()} item(s) → ${dest || 'choose a destination folder'}`;
 const ref=destFull(),bad=destinationInvalid(ref,entries);
 $('#xferOK').disabled=!okEnabled({dest:ref,entries,pending});
 // A picked folder whose name the field cannot hold verbatim (a newline, and
 // anything an <input> normalises) is still the one that will be used — say so
 // rather than letting the box look authoritative when it is not.
 const shown=picked && destText()!==picked.path ? 'The box shows a simplified spelling; the folder picked above is the one that will be used.' : '';
 const why=!dest ? '' : !dest.startsWith('/') ? 'Use an absolute path, starting with /.'
  : bad ? `That folder is one of the items being ${mode==='move' ? 'moved' : 'copied'}, or inside one.` : shown;
 $('#xferWhy').textContent=why; $('#xferWhy').hidden=!why;
}

function pick(entry) {
 picked=entry;
 $('#xferPath').value=entry.path; // may be normalised by the input; picked stays authoritative
 highlight(entry.path);
 paint();
}

// openTransfer is the one entry point: the toolbar, the context menu and a
// Ctrl+V paste all land here. start is where the PICKER opens (the folder the
// user is looking at); dest is what is PRESELECTED as the destination — a
// pathRef, not a string, so a paste carries the current folder's authoritative
// bytes and not just its display spelling. The toolbar leaves it unset so
// nothing can be submitted by reflex. consumed is the clipboard object a paste
// is spending, captured by the caller AT PASTE TIME and kept with the dialog.
export function openTransfer({mode:kind,entries:items,dest=null,start='',consumed=null}) {
 if (!state.session?.canWrite || !items?.length) return;
 // A new dialog: anything still in flight from the last one stops owning it.
 generation++;
 mode=kind; entries=items; consumedBoard=consumed; pending=false;
 // A preselected folder counts as picked: it is the authoritative reference,
 // whatever the field ends up displaying.
 picked=dest ? {path:dest.path,pathB64:dest.pathB64} : null;
 $('#xferTitle').textContent=transferTitle(mode,entries.length);
 $('#xferOK').textContent=label();
 $('#xferPath').value=dest?.path || '';
 for (const radio of $('#dlgTransfer').querySelectorAll('input[name=xferConflict]')) radio.checked=radio.value==='skip';
 // Crossing is a hero-only question, gated exactly as the delete dialog gates it.
 const hero=state.session?.family==='quts_hero';
 $('#xferCrossRow').hidden=!hero;
 if (!hero) $('#xferCross').checked=false; else $('#xferCross').checked=true;
 setError(''); paint();
 openDialog('#dlgTransfer');
 $('#xferPath').focus(); $('#xferPath').select?.();
 const valid=sessionGuard(),mine=generation;
 renderTree({container:$('#xferTree'),onPick:pick,expandTo:dest?.path||start||state.path,volumeRoots:true})
  .then(() => { if (valid() && mine===generation) highlight(destPath()); })
  .catch(err => { if (valid() && mine===generation) setError(err.message); });
}

// submit posts the transfer and KEEPS THE DIALOG OPEN until the server has
// accepted it. A refusal (a protected destination, a bad policy, the routes not
// deployed yet) leaves every choice the user made in place to be corrected —
// and the message is shown inside the dialog, because a modal is in the top
// layer and neither the status bar nor a toast is readable behind it.
//
// One request at a time: `pending` covers the whole exchange — the pre-flight,
// the confirmation, and the token re-post are ONE submission, and the button
// cannot come back to life under a repaint while any of it is outstanding.
async function submit() {
 if (!okEnabled({dest:destFull(),entries,pending})) return;
 const kind=mode,items=entries,dest=destPath(),policy=conflict();
 // The marking this dialog is spending, recorded when the paste opened it — not
 // whatever the clipboard happens to hold now. Only THIS object may be cleared
 // when the server accepts, however long that takes.
 const consumed=consumedBoard;
 const body={paths:items.map(pathArgs),dest:destRef(),conflict:policy,crossMounts:crossMounts()};
 const valid=sessionGuard(),mine=generation;
 // live() is the whole dismissal story: the user may abandon a 30-second
 // pre-flight at any moment, and when they do this submission stops being
 // allowed to touch the dialog — its own or, worse, the next one.
 const live = () => valid() && submissionLive({started:mine,current:generation,open:$('#dlgTransfer').open});
 pending=true; paint(); setError('');
 try {
  const res=await runMutation(`api/jobs/${kind}`,body,async confirm => {
   // Dismissed while the pre-flight ran: decline, so the token is never spent
   // and no job is ever created for an operation nobody is waiting on.
   if (!live()) return false;
   const {body:facts,why}=transferSummary(confirm.summary);
   const grade=transferGrade(confirm.summary);
   return confirmDialog({
    title:kind==='move' ? 'Confirm move' : 'Confirm copy',
    body:`${kind==='move' ? 'Move' : 'Copy'} ${facts} to ${dest}?`,
    why,
    // Only an overwrite destroys something that is already there; scale and a
    // cross-volume move are loud, not dangerous.
    danger:policy==='overwrite',
    phrase:grade===2 ? items[0].name : '',
    okLabel:kind==='move' ? 'Move' : 'Copy',
   });
  });
  if (!valid()) return;
  if (res===null) return; // declined (or abandoned); the dialog stays as it was
  // The job exists the moment the server says 202, so it is tracked even if the
  // dialog was dismissed in the meantime — an accepted transfer must never run
  // where nobody can see or cancel it. Only the DIALOG-owning steps below are
  // conditional: closing someone else's dialog is the harm this guards.
  trackJob(res.job);
  if (live()) $('#dlgTransfer').close();
  // The 202 says ACCEPTED, not done (M2-A finding W9): the job panel owns the
  // outcome, so this only says what was asked for.
  announce(`${kind==='move' ? 'Moving' : 'Copying'} ${items.length.toLocaleString()} item(s) to ${dest}…`);
  const board=clipboardAfterPaste(state.clipboard,consumed);
  if (board!==state.clipboard) update({clipboard:board});
 } catch(err) {
  const message=transferErrorMessage(err,kind);
  if (!live()) return;
  setError(message); error(new Error(message));
 // Only this submission's own lock is released: a stale request finishing must
 // not unlock a NEWER dialog that has a request of its own in flight.
 } finally { if (mine===generation) pending=false; if (live()) paint(); }
}

// --- clipboard ---------------------------------------------------------------

// markGeneration counts the marking GESTURES, so a finished one can tell whether
// it is still the user's current intent.
let markGeneration=0;

// publishMarking says whether a marking that has finished resolving may still be
// published. Marking is asynchronous — selectionEntries fetches any pages a
// Shift-range spans that were never loaded — so a Ctrl+X over unloaded rows can
// still be in flight when the user marks something else with Ctrl+C. The later
// gesture is the current intent; the older request must publish nothing rather
// than land on top of it. It used to win by finishing last, and Ctrl+V then
// moved the wrong items, with the wrong operation.
export function publishMarking(captured,current) { return captured===current; }

// markClipboard is Ctrl+C / Ctrl+X. It resolves the selection the same way
// deleteSelection does — fetching any selected pages that were never loaded —
// so a Shift-range spanning unloaded pages is marked in full or not at all.
export async function markClipboard(kind) {
 if (!state.session?.canWrite) return;
 const mine=++markGeneration,valid=sessionGuard();
 let items;
 // A superseded gesture says nothing at all — not even its failure. The user has
 // moved on to another marking, and the error belongs to the one they abandoned.
 const live = () => valid() && publishMarking(mine,markGeneration);
 try { items=await selectionEntries(); }
 catch(err) { if (live()) error(err); return; }
 if (!live()) return;
 if (items===null) { error(new Error('Select items individually to copy or move them in this version.')); return; }
 if (!items.length) return;
 update({clipboard:{mode:kind,entries:items}});
 toast(clipboardToast(kind,items.length));
}

export function pasteHere() {
 const board=state.clipboard;
 if (!board?.entries?.length) { announce('Nothing is marked. Press Ctrl+C or Ctrl+X first.'); return; }
 // The current folder's own reference, bytes included — state.path alone is the
 // display spelling and a non-UTF-8 name does not survive it. `board` is handed
 // over as well: the dialog spends THIS marking, whatever the clipboard becomes.
 openTransfer({mode:board.mode,entries:board.entries,dest:{path:state.path,pathB64:state.pathB64},consumed:board});
}

// transferSelection is the toolbar action. The destination is left empty on
// purpose: a copy needs somewhere to go, and preselecting the folder the items
// are already in would make Enter a no-op refusal.
export async function transferSelection(kind) {
 let items;
 try { items=await selectionEntries(); }
 catch(err) { error(err); return; }
 if (items===null) { error(new Error('Select items individually to copy or move them in this version.')); return; }
 if (!items.length) return;
 openTransfer({mode:kind,entries:items,start:state.path});
}

export function initTransfer() {
 $('#btnCopy').addEventListener('click',() => transferSelection('copy'));
 $('#btnMove').addEventListener('click',() => transferSelection('move'));
 // Context-menu entries, contributed the way actions.js contributes its own.
 extraActions.push({label:'Copy to…',show:() => !!state.session?.canWrite,run:e => openTransfer({mode:'copy',entries:[e],start:state.path})});
 extraActions.push({label:'Move to…',show:() => !!state.session?.canWrite,run:e => openTransfer({mode:'move',entries:[e],start:state.path})});
 $('#xferOK').addEventListener('click',() => submit());
 // Editing the field is the ONLY thing that gives up a picked reference.
 $('#xferPath').addEventListener('input',() => { picked=null; highlight(destText()); paint(); });
 $('#xferPath').addEventListener('keydown',ev => { if (ev.key==='Enter' && !$('#xferOK').disabled) { ev.preventDefault(); submit(); } });
 // Drop the picker when the dialog closes: it holds a whole loaded subtree, and
 // the next open must not show a listing from before the last change.
 // Dismissal is always allowed, even mid-pre-flight: the lock goes with the
 // dialog, and submissionLive keeps the abandoned request from coming back.
 $('#dlgTransfer').addEventListener('close',() => { $('#xferTree').replaceChildren(); entries=[]; picked=null; consumedBoard=null; pending=false; setError(''); });
 // A clipboard marked as one user must not survive into another's session.
 // Assigned rather than update()d: nothing renders from it, and notifying from
 // inside a notification is a re-entrancy nobody needs.
 subscribe(() => { if (!state.session) state.clipboard=null; });
}
