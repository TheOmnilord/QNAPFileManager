// Run with: node --test internal/web/search_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {rootRef,searchRequest,searchProblem,resultsTitle,mountsNote,resultRow,escapeReturnsToListing,searchOutcomeWins,claimResults,revealNeedsHidden,searchTeardown,resultLink,KINDS} from './static/js/search.js';
import {activeView,actionsEnabledFor} from './static/js/state.js';
import {revealIndex,revealApplies,revealFilter,matchesFilter} from './static/js/list.js';

// b64 is the byte-safe encoding the server uses for pathB64: base64url of the
// RAW bytes, so a path that is not valid UTF-8 survives the trip.
const b64 = bytes => Buffer.from(bytes,'binary').toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
// Counts are grouped with toLocaleString, whose separator is the viewer's, so
// the expectations are built the same way rather than pinning one locale.
const n = value => value.toLocaleString();

const here = {path:'/share/Photos',pathB64:b64('/share/Photos')};

// --- the root ----------------------------------------------------------------

test('rootRef keeps the current folder’s bytes only while the field is UNTOUCHED', () => {
 // Untouched is expressed by the dialog handing back the reference it opened
 // with (or nothing at all) — never by text that happens to look the same.
 assert.deepEqual(rootRef(here,here),{pathB64:here.pathB64});
 assert.deepEqual(rootRef(null,here),{pathB64:here.pathB64});
 assert.deepEqual(rootRef(undefined,here),{pathB64:here.pathB64});
});

test('rootRef takes an edited field at its word, spaces and all', () => {
 assert.deepEqual(rootRef('/share/Other',here),{path:'/share/Other'});
 // A trailing space is far more likely a real name on a NAS than a typo, and
 // is never trimmed; a single trailing newline is paste debris and is.
 assert.deepEqual(rootRef('/share/Photos ',here),{path:'/share/Photos '});
 assert.deepEqual(rootRef('/share/Other\n',here),{path:'/share/Other'});
});

test('an EDITED root never recovers a byte reference, even from identical text', () => {
 // Text equal to the current folder's display is still TYPED text, and typed
 // text is UTF-8 by construction. Recovering the ref from it was the bug.
 assert.deepEqual(rootRef('/share/Photos',here),{path:'/share/Photos'});
});

test('rootRef accepts a reference directly and prefers its bytes', () => {
 assert.deepEqual(rootRef({path:'/x',pathB64:b64('/x')},here),{pathB64:b64('/x')});
 assert.deepEqual(rootRef({path:'/typed'},here),{path:'/typed'});
});

test('rootRef falls back to the current folder’s text when it has no bytes', () => {
 assert.deepEqual(rootRef(null,{path:'/share'}),{path:'/share'});
 assert.deepEqual(rootRef(null,null),{path:''});
});

test('an edited root cannot steal the ORIGINAL folder’s bytes through a lookalike', () => {
 // The current folder is "/share/\xff", which displays as "/share/�". A
 // SIBLING really called "/share/�" displays identically. Typing that sibling
 // — deliberately, character by character — used to match the current folder's
 // display and send ITS bytes, searching the directory the user had just left.
 const odd = {path:'/share/�',pathB64:b64('/share/\xff')};
 assert.deepEqual(rootRef('/share/�',odd),{path:'/share/�'});     // the sibling, as typed
 assert.deepEqual(rootRef('/share/elsewhere',odd),{path:'/share/elsewhere'});
 // Untouched, the odd folder is still searched by its own bytes — which is the
 // whole point of keeping the reference.
 assert.deepEqual(rootRef(odd,odd),{pathB64:odd.pathB64});
});

// --- the request body --------------------------------------------------------

test('searchRequest sends only the flags that are on', () => {
 const body = searchRequest({query:'report',glob:false,hidden:false,crossMounts:false,kind:'any',root:here},here);
 assert.deepEqual(body,{roots:[{pathB64:here.pathB64}],query:'report'});
});

test('searchRequest carries every flag that is on, and the kind when it narrows', () => {
 const body = searchRequest({query:'*.log',glob:true,hidden:true,crossMounts:true,kind:'file',root:here},here);
 assert.deepEqual(body,{roots:[{pathB64:here.pathB64}],query:'*.log',glob:true,hidden:true,crossMounts:true,kind:'file'});
 assert.equal(searchRequest({query:'x',kind:'dir'},here).kind,'dir');
 // "any" is the route's own default and says nothing.
 assert.equal('kind' in searchRequest({query:'x',kind:'any'},here),false);
 assert.equal('kind' in searchRequest({query:'x',kind:'nonsense'},here),false);
 assert.deepEqual(KINDS,['any','file','dir']);
});

test('searchRequest never trims the query — a name can begin or end with a space', () => {
 assert.equal(searchRequest({query:' draft ',root:'/share/Photos'},here).query,' draft ');
 assert.equal(searchRequest({},here).query,'');
});

test('searchProblem is the submit gate and nothing more', () => {
 assert.equal(searchProblem({query:'x',roots:[{path:'/share'}]}),'');
 assert.equal(searchProblem({query:'x',roots:[{pathB64:'abc'}]}),'');
 assert.match(searchProblem({query:'',roots:[{path:'/share'}]}),/Type something/);
 assert.match(searchProblem({query:'   ',roots:[{path:'/share'}]}),/Type something/);
 assert.match(searchProblem({query:'x',roots:[{path:'share'}]}),/absolute path/);
 assert.match(searchProblem({query:'x',roots:[{path:''}]}),/absolute path/);
 // Whether the folder exists, and whether this user may traverse it, belong to
 // the server and are never guessed at here.
 assert.equal(searchProblem({query:'x',roots:[{path:'/nowhere/at/all'}]}),'');
});

// --- the results header ------------------------------------------------------

test('resultsTitle says how many, for what, and where', () => {
 assert.equal(resultsTitle(3,'report','/share/Photos',''),'3 results for “report” in /share/Photos');
 assert.equal(resultsTitle(1,'report','/share',''),'1 result for “report” in /share');   // singular
 assert.equal(resultsTitle(0,'report','/share',''),'0 results for “report” in /share');
 assert.equal(resultsTitle(1204,'a','/share',''),`${n(1204)} results for “a” in /share`);
});

test('resultsTitle never lets a capped search read as a complete one', () => {
 // The server's own sentence is what says the rest of the truth.
 assert.equal(resultsTitle(1000,'a','/share','first 1000 of many'),
  `${n(1000)} results for “a” in /share · first 1000 of many`);
});

// --- one row -----------------------------------------------------------------

test('resultRow splits a hit into the row it shows', () => {
 const row = resultRow({name:'report.pdf',path:'/share/Docs/2026/report.pdf',type:'file',size:4096,mtime:'2026-09-13T10:00:00Z'});
 assert.equal(row.name,'report.pdf');
 assert.equal(row.parent,'/share/Docs/2026');
 assert.equal(row.size,n(4096));
 assert.equal(row.dir,false);
 assert.ok(row.modified.length > 0);
});

test('resultRow gives a folder a dash for its size, as the listing does', () => {
 const row = resultRow({name:'2026',path:'/share/Docs/2026',type:'dir',size:4096,mtime:'2026-09-13T10:00:00Z'});
 assert.equal(row.size,'—');
 assert.equal(row.dir,true);
 assert.equal(row.parent,'/share/Docs');
});

test('resultRow computes the parent in BYTES, so a click lands in the right folder', () => {
 // A hit under a directory whose name is not valid UTF-8: slicing the DISPLAY
 // path would navigate to a lookalike, or to nothing at all.
 const raw = '/share/\xff/notes.txt';
 const row = resultRow({name:'notes.txt',path:'/share/�/notes.txt',pathB64:b64(raw),type:'file',size:12,mtime:'2026-09-13T10:00:00Z'});
 assert.equal(row.parentRaw,'/share/\xff');
 assert.equal(row.parentRef.pathB64,b64('/share/\xff'));
});

test('resultRow gives a top-level hit the root for a parent', () => {
 const row = resultRow({name:'etc',path:'/etc',type:'dir',size:0,mtime:'2026-09-13T10:00:00Z'});
 assert.equal(row.parent,'/');
 assert.equal(row.parentRaw,'/');
});

test('resultRow survives a hit with nothing useful in it', () => {
 const row = resultRow(null);
 assert.equal(row.parent,'/');
 assert.equal(row.size,'0');
 assert.equal(row.modified,'');
});

// --- following a hit back into the listing (round 2, findings 1 and 4) -------

// Two files whose names DISPLAY identically: one really is the three bytes of
// U+FFFD, the other is the single byte 0xff that a viewer also draws as “�”.
const literal = {name:'�',path:'/share/x/�',type:'file'};
const odd = {name:'�',path:'/share/x/�',pathB64:b64('/share/x/\xff'),type:'file'};

test('revealIndex tells two lookalike names apart, whichever order they are in', () => {
 // The bug: the name comparison matched whichever came first, and the rename
 // or delete the user then performed acted on the other file.
 assert.equal(revealIndex(new Map([[0,[literal,odd]]]),500,odd),1);
 assert.equal(revealIndex(new Map([[0,[literal,odd]]]),500,literal),0);
 assert.equal(revealIndex(new Map([[0,[odd,literal]]]),500,odd),0);
 assert.equal(revealIndex(new Map([[0,[odd,literal]]]),500,literal),1);
});

test('revealIndex counts the page it found the entry on', () => {
 assert.equal(revealIndex(new Map([[2,[{path:'/a'},{path:'/share/x/�'}]]]),500,literal),1001);
 assert.equal(revealIndex(new Map(),500,literal),-1);
 assert.equal(revealIndex(null,500,literal),-1);
});

test('revealIndex matches nothing rather than matching by resemblance', () => {
 const pages = new Map([[0,[literal,{name:'broken',pathB64:'not base64!!'}]]]);
 assert.equal(revealIndex(pages,500,{pathB64:'not base64!!'}),-1); // unknowable want
 assert.equal(revealIndex(pages,500,null),-1);
 assert.equal(revealIndex(pages,500,{}),-1);
 assert.equal(revealIndex(pages,500,{name:'broken'}),-1);          // a name is not an identity
});

const pending = (parentRaw,generation) => ({name:'report.txt',path:'/a/report.txt',
 parent:'/a',parentB64:b64(parentRaw),generation});

test('revealApplies refuses a listing that is not the folder the hit asked for', () => {
 // Click /a/report.txt, change your mind and go to /b before /a answers: /b's
 // load used to consume the request and select /b/report.txt.
 assert.equal(revealApplies(pending('/a',3),{path:'/a',pathB64:b64('/a')},4),true);
 assert.equal(revealApplies(pending('/a',3),{path:'/b',pathB64:b64('/b')},4),false);
});

test('revealApplies compares the destination in bytes too', () => {
 assert.equal(revealApplies(pending('/share/\xff',3),{path:'/share/�',pathB64:b64('/share/\xff')},4),true);
 assert.equal(revealApplies(pending('/share/\xff',3),{path:'/share/�',pathB64:b64('/share/\xfe')},4),false);
});

test('revealApplies refuses a load that was already in flight when it was asked', () => {
 // A listing that started BEFORE the click describes the folder being left.
 assert.equal(revealApplies(pending('/a',5),{path:'/a',pathB64:b64('/a')},5),false);
 assert.equal(revealApplies(pending('/a',5),{path:'/a',pathB64:b64('/a')},4),false);
 assert.equal(revealApplies(pending('/a',5),{path:'/a',pathB64:b64('/a')},6),true);
});

test('revealApplies says no to nothing at all', () => {
 assert.equal(revealApplies(null,{path:'/a'},4),false);
 assert.equal(revealApplies({generation:1},{path:'/a'},4),false);   // no destination named
 assert.equal(revealApplies(pending('/a',3),null,4),false);
 assert.equal(revealApplies(pending('/a',3),{},4),false);
});

// --- revealing a hidden hit (round 5, finding 1) -----------------------------

test('revealNeedsHidden: a hidden hit needs the listing’s toggle turned on', () => {
 // A search may be told to include hidden items; the LISTING has its own,
 // separate toggle. A hit on ".env" was found and shown, and then the folder
 // opened without it and the reveal found nothing to select.
 assert.equal(revealNeedsHidden({name:'.env',path:'/share/x/.env'},false),true);
 assert.equal(revealNeedsHidden({name:'notes.txt',hidden:true},false),true);  // the server's own answer
});

test('revealNeedsHidden does nothing when the toggle is already on', () => {
 assert.equal(revealNeedsHidden({name:'.env'},true),false);
 assert.equal(revealNeedsHidden({name:'notes.txt',hidden:true},true),false);
});

test('revealNeedsHidden leaves an ordinary hit alone', () => {
 // Turning hidden items on unasked is a visible change to the listing; it is
 // made only when it is the difference between selecting the hit and not.
 assert.equal(revealNeedsHidden({name:'notes.txt',path:'/share/x/notes.txt'},false),false);
 assert.equal(revealNeedsHidden({name:'a.b.c'},false),false);       // dots, but not a leading one
 assert.equal(revealNeedsHidden({name:''},false),false);
 assert.equal(revealNeedsHidden(null,false),false);
 assert.equal(revealNeedsHidden(null,true),false);
});

// --- revealing through a quick filter (round 4, finding 1) -------------------

const hit = name => ({name,path:`/share/x/${name}`,type:'file'});

test('revealFilter leaves alone a filter the hit already matches', () => {
 assert.deepEqual(revealFilter('rep',hit('report.txt')),{clear:false,note:''});
 assert.deepEqual(revealFilter('REP',hit('report.txt')),{clear:false,note:''}); // case, like the listing
 assert.deepEqual(revealFilter('',hit('report.txt')),{clear:false,note:''});
 assert.deepEqual(revealFilter(null,hit('report.txt')),{clear:false,note:''});
});

test('revealFilter clears a filter that would hide the hit, and names both', () => {
 // The bug: the row was selected, the filter hid it, render() moved focus
 // elsewhere, and Delete/Copy then acted on a selection nobody could see.
 const {clear,note} = revealFilter('invoice',hit('report.txt'));
 assert.equal(clear,true);
 assert.match(note,/invoice/);
 assert.match(note,/report\.txt/);
});

test('revealFilter agrees with the listing about what is visible', () => {
 // It MUST be the same predicate render() and navigable() use, or a row can be
 // "not hidden" here and hidden there — which is the whole bug, reintroduced.
 for (const [filter,name] of [['rep','report.txt'],['REP','report.txt'],['x','report.txt'],
                              ['','report.txt'],['ö','Bilder ö.txt'],['Ö','Bilder ö.txt']]) {
  assert.equal(revealFilter(filter,hit(name)).clear,!matchesFilter(filter,name),`${filter} / ${name}`);
 }
});

test('revealFilter clears rather than trusting an entry with no name', () => {
 assert.equal(revealFilter('x',null).clear,true);
 assert.equal(revealFilter('x',{}).clear,true);
 assert.equal(revealFilter('',null).clear,false);
});

// --- a superseded search (round 2 finding 3, round 3) ------------------------

test('only the latest search may paint the results pane', () => {
 // A slow, then B; B displays; A lands later and used to replace B's results
 // under B's header.
 const owner = claimResults(null,{seq:1,id:'job-b'},1);
 assert.equal(searchOutcomeWins('job-b',owner),true);
 assert.equal(searchOutcomeWins('job-a',owner),false);
});

test('a 202 that arrives OUT OF ORDER cannot take the pane from the newer search', () => {
 // The round-3 bug. Ownership was recorded from the response, and the response
 // order is not the submission order: A is submitted first but its pre-flight
 // is slower, so B's 202 lands first and A's lands second — and A quietly took
 // the pane back, after which B's own completion was judged "superseded" and
 // thrown away. The user's newest search was the one that never appeared.
 let owner = null;
 // A takes ticket 1 and B takes ticket 2, both before either asks the server.
 // B answers first, while its ticket is the latest issued.
 owner = claimResults(owner,{seq:2,id:'job-b'},2);
 assert.deepEqual(owner,{seq:2,id:'job-b'});
 // A's 202 lands late. Its ticket is no longer the latest, so it claims nothing.
 owner = claimResults(owner,{seq:1,id:'job-a'},2);
 assert.deepEqual(owner,{seq:2,id:'job-b'});
 // So A's completion is dismissed and B's — the search the user is waiting on —
 // is the one that paints.
 assert.equal(searchOutcomeWins('job-a',owner),false);
 assert.equal(searchOutcomeWins('job-b',owner),true);
});

test('in the ordinary order the newer search still takes the pane', () => {
 let owner = claimResults(null,{seq:1,id:'job-a'},1);
 assert.deepEqual(owner,{seq:1,id:'job-a'});
 // B is submitted (ticket 2) and answers; it is the latest and takes over.
 owner = claimResults(owner,{seq:2,id:'job-b'},2);
 assert.deepEqual(owner,{seq:2,id:'job-b'});
 assert.equal(searchOutcomeWins('job-a',owner),false);
});

test('claimResults keeps the standing owner rather than inventing one', () => {
 const owner = {seq:2,id:'job-b'};
 assert.equal(claimResults(owner,null,2),owner);
 assert.equal(claimResults(owner,{seq:2},2),owner);        // a 202 with no job id
 assert.equal(claimResults(owner,{seq:3,id:'job-c'},2),owner); // a ticket nobody issued
 assert.equal(claimResults(null,{seq:1,id:'job-a'},2),null);
});

test('a search with no id, or no owner at all, paints nothing', () => {
 assert.equal(searchOutcomeWins('',{seq:1,id:''}),false);
 assert.equal(searchOutcomeWins(null,null),false);
 assert.equal(searchOutcomeWins(undefined,undefined),false);
 assert.equal(searchOutcomeWins('job-a',null),false);
 assert.equal(searchOutcomeWins('job-a',{seq:1,id:'job-b'}),false);
});

// --- a symlink nobody followed (round 10, finding 1) -------------------------

test('an uninspected symlink says where it points and claims nothing more', () => {
 // Search does not follow links, so a hit carries linkTarget and nothing else.
 // The listing's renderer read that absence as proof of breakage and struck
 // every symlink in every result set through as "→ ? (broken)".
 const hit = {name:'latest',path:'/share/x/latest',type:'symlink',isSymlink:true,linkTarget:'../releases/2026-09'};
 assert.deepEqual(resultLink(hit),{
  text:'→ ../releases/2026-09',
  state:'uninspected',
  title:'Symlink — search does not follow links, so its target was not inspected.',
 });
 assert.ok(!resultLink(hit).text.includes('broken'));
 assert.ok(!resultLink(hit).text.includes('?'));
});

test('a symlink with nothing to say says nothing at all', () => {
 // Not even a "?": a question mark is a claim too, and the wrong one.
 assert.equal(resultLink({name:'l',type:'symlink',isSymlink:true}),null);
 assert.equal(resultLink({name:'l',type:'symlink',isSymlink:true,linkTarget:''}),null);
});

test('resultLink ignores anything that is not a symlink', () => {
 assert.equal(resultLink({name:'a.txt',type:'file'}),null);
 assert.equal(resultLink({name:'d',type:'dir'}),null);
 assert.equal(resultLink(null),null);
});

test('a link that WAS inspected keeps the listing’s verdict, broken or not', () => {
 // Where something really did follow the link, the honest answer is the one the
 // listing gives; the evidence is linkResolved, or at least a targetType.
 const healthy = {type:'symlink',isSymlink:true,linkTarget:'../a',linkResolved:'/share/a',targetType:'dir'};
 assert.deepEqual(resultLink(healthy),{text:'→ ../a',state:'ok',title:''});
 const reallyBroken = {type:'symlink',isSymlink:true,linkTarget:'../gone',targetType:''};
 assert.equal(resultLink({...reallyBroken,targetType:'file'}).state,'broken'); // inspected, nothing there
 assert.equal(resultLink({...reallyBroken,targetType:'file'}).text,'→ ../gone (broken)');
 // Byte-spelled resolution counts as evidence too.
 assert.equal(resultLink({type:'symlink',isSymlink:true,linkTarget:'../a',linkResolvedB64:'L2E'}).state,'ok');
});

// --- what a search leaves behind (round 9, finding 2) ------------------------

const alice = {user:'alice',uid:1000};
const bob = {user:'bob',uid:1001};

test('searchTeardown clears everything a search leaves behind, not just the hits', () => {
 // The bug: only searchResults was cleared, and only when it happened to be
 // set. Alice followed a hit, signed out while the parent was still loading,
 // and Bob's listing satisfied HER pending reveal and selected her target.
 const patch = searchTeardown(alice,null);
 assert.deepEqual(patch,{searchResults:null,searchJob:null,pendingReveal:null});
 // All three, named explicitly, so adding a fourth without clearing it fails here.
 assert.deepEqual(Object.keys(patch).sort(),['pendingReveal','searchJob','searchResults']);
});

test('searchTeardown fires for a switch as well as a sign-out', () => {
 assert.notEqual(searchTeardown(alice,bob),null);
 assert.notEqual(searchTeardown(alice,null),null);
});

test('searchTeardown leaves a refresh completely alone', () => {
 // A read-only toggle must not throw away the results the user is reading.
 assert.equal(searchTeardown(alice,{...alice,readOnly:true}),null);
 assert.equal(searchTeardown(alice,{...alice,csrf:'rotated'}),null);
 assert.equal(searchTeardown(null,alice),null);   // the first connect
});

test('searchTeardown does not depend on there being results to clear', () => {
 // The early return that skipped the teardown when searchResults was null is
 // exactly what let the pending reveal through.
 assert.notEqual(searchTeardown(alice,bob),null);
 assert.equal(searchTeardown(alice,bob).pendingReveal,null);
});

// --- Escape ------------------------------------------------------------------

// --- the action gate (round 1, finding 1) ------------------------------------

test('activeView names the pane that is on screen, not the state that exists', () => {
 assert.equal(activeView({searchResults:{hits:[],open:true}}),'results');
 // Results KEPT but closed: the listing is back, and so are its actions.
 assert.equal(activeView({searchResults:{hits:[{name:'a'}],open:false}}),'listing');
 assert.equal(activeView({searchResults:null}),'listing');
 assert.equal(activeView({}),'listing');
 assert.equal(activeView(null),'listing');
});

test('a selection made before a search counts for NOTHING while the results cover it', () => {
 // The bug: 12 items selected, then a search; Delete, Ctrl+X, Rename and
 // Copy to… all stayed live against twelve rows nobody could see.
 assert.deepEqual(actionsEnabledFor('results',12),{view:'results',listing:false,mutate:false,count:0});
 assert.deepEqual(actionsEnabledFor('results',0),{view:'results',listing:false,mutate:false,count:0});
});

test('the listing view passes its selection through unchanged', () => {
 assert.deepEqual(actionsEnabledFor('listing',12),{view:'listing',listing:true,mutate:true,count:12});
 assert.deepEqual(actionsEnabledFor('listing',0),{view:'listing',listing:true,mutate:true,count:0});
});

test('the gate never invents a selection out of a nonsense count', () => {
 assert.equal(actionsEnabledFor('listing',-4).count,0);
 assert.equal(actionsEnabledFor('listing',NaN).count,0);
 assert.equal(actionsEnabledFor('listing',undefined).count,0);
 assert.equal(actionsEnabledFor('listing',2.9).count,2);
});

test('an unknown view is treated as the listing, never as a licence', () => {
 // Only the results view suppresses; anything else is the ordinary case, so a
 // future third view cannot silently disable the whole toolbar.
 assert.equal(actionsEnabledFor('',3).mutate,true);
 assert.equal(actionsEnabledFor(undefined,3).mutate,true);
});

test('escapeReturnsToListing is true only while a results view is actually open', () => {
 assert.equal(escapeReturnsToListing({searchResults:{hits:[],open:true}}),true);
 assert.equal(escapeReturnsToListing({searchResults:{hits:[{name:'a'}],open:true}}),true);
 // Kept, but closed: the hits survive so following one is not a one-way door,
 // and Escape must not then "close" something that is not on screen.
 assert.equal(escapeReturnsToListing({searchResults:{hits:[],open:false}}),false);
 assert.equal(escapeReturnsToListing({searchResults:null}),false);
 assert.equal(escapeReturnsToListing({}),false);
 assert.equal(escapeReturnsToListing(null),false);
});

// --- mount points the walk did not enter (decision 9, amended) --------------

test('mountsNote says where the search did not look, and promises nothing more', () => {
 assert.equal(mountsNote({local:0,network:0},{crossMounts:true,canCross:true}),'');
 assert.equal(mountsNote(),'');
 // Local mounts are only reported: one may be a root the guard refuses, and
 // the note does not ask (Astra r3), so it offers no next step.
 assert.equal(mountsNote({local:1},{crossMounts:true,canCross:true}),
  '1 mounted folder was not searched.');
 assert.equal(mountsNote({local:3},{crossMounts:true,canCross:true}),
  `${n(3)} mounted folders were not searched.`);
 // Unticked and on screen: the box MAY help (it does not reach another pool
 // from inside a pool), so it is offered as a possibility.
 assert.equal(mountsNote({local:2},{crossMounts:false,canCross:true}),
  `${n(2)} mounted folders were not searched. Ticking “Include mounted sub-folders” may include them.`);
 // No box on screen (QTS): no advice about one.
 assert.equal(mountsNote({local:2},{crossMounts:false,canCross:false}),
  `${n(2)} mounted folders were not searched.`);
 for (const local of [1,5]) for (const crossMounts of [false,true]) {
  assert.doesNotMatch(mountsNote({local},{crossMounts,canCross:true}),/search (it|them|inside)|directly/i);
 }
});

test('a network share is reported, never offered as somewhere to search', () => {
 // Neither crossing nor a search rooted inside it reaches a network share, so
 // no sentence about one may suggest either.
 const one = mountsNote({network:1},{crossMounts:false,canCross:true});
 assert.equal(one,'1 network share was skipped; network shares cannot be searched.');
 const both = mountsNote({local:1,network:2},{crossMounts:true,canCross:true});
 assert.equal(both,`1 mounted folder was not searched. ${n(2)} network shares were skipped; network shares cannot be searched.`);
 assert.doesNotMatch(mountsNote({network:4},{crossMounts:false,canCross:true}),/Tick|search (it|them|inside)/i);
});
