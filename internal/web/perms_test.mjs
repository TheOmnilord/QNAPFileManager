// Run with: node --test internal/web/perms_test.mjs
//
// The permissions dialog's dispatch (M3 contract §10, §12) and the properties
// dialog's size-job wiring (§8.4). What is tested here is what Apply POSTS and
// what a dialog does to the job it started — the two things a screenshot cannot
// show and a packet capture should not have to.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {OCTAL_REFUSAL,applyBlocked,applyPlan,applyScope,chownGateMessage,clearIdCache,impactNote,impactRoots,impactText,loadIds,octalState,permsApplies,reportResult} from './static/js/perms.js';
import {update} from './static/js/state.js';
import {createSizeRunner,flagsText,modeText,ownerText,propsSections,sizeReport,sizeRequest} from './static/js/props.js';
import {warningCode,warningLine,warningsLabel} from './static/js/jobs.js';
import {actionMessage} from './static/js/actions.js';
import {EMPTY,SETUID,jobSpecs,parseOctal,toggleBit} from './static/js/perm.js';

const dir = (path,rest = {}) => ({path,name:path.split('/').pop(),type:'dir',mode:'0755',uid:0,gid:0,...rest});
const file = (path,rest = {}) => ({path,name:path.split('/').pop(),type:'file',mode:'0644',uid:1003,gid:100,...rest});
// b64 is the byte-safe encoding the server uses for pathB64.
const b64 = bytes => Buffer.from(bytes,'binary').toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

// --- what Apply posts (§10) ---------------------------------------------------

test('one item, not recursive, is the SYNC route with a mask and a value', () => {
 const plan = applyPlan({entries:[file('/share/Public/a.txt')],spec:parseOctal('0640')});
 assert.equal(plan.length,1);
 assert.equal(plan[0].endpoint,'api/fs/chmod');
 assert.deepEqual(plan[0].body,{path:'/share/Public/a.txt',mask:0o7777,value:0o640});
 assert.equal(plan[0].job,undefined);
});

test('a path with non-UTF-8 bytes travels as pathB64, as everywhere else', () => {
 const entry = {...file('/share/Public/odd'),pathB64:b64('/share/Public/\xff')};
 const [request] = applyPlan({entries:[entry],spec:parseOctal('0600')});
 assert.deepEqual(request.body,{pathB64:b64('/share/Public/\xff'),mask:0o7777,value:0o600});
 assert.equal('path' in request.body,false);
});

test('a partial mask — a mixed selection’s touched bits — survives to the wire', () => {
 const spec = toggleBit(EMPTY,0o020,true);
 const [request] = applyPlan({entries:[file('/share/Public/a.txt')],spec});
 assert.deepEqual(request.body,{path:'/share/Public/a.txt',mask:0o020,value:0o020});
});

test('#pFollowLinks is the only way a chmod reaches a symlink’s target (§1.4)', () => {
 const link = {...file('/share/Public/link'),type:'symlink',isSymlink:true};
 const plain = applyPlan({entries:[link],spec:parseOctal('0755')});
 assert.equal('follow' in plain[0].body,false);
 const followed = applyPlan({entries:[link],spec:parseOctal('0755'),follow:true});
 assert.equal(followed[0].body.follow,true);
});

test('more than one item, or recursive, is a JOB (§10)', () => {
 const many = applyPlan({entries:[file('/share/a'),file('/share/b')],spec:parseOctal('0644')});
 assert.equal(many[0].endpoint,'api/jobs/chmod');
 assert.equal(many[0].job,true);
 assert.deepEqual(many[0].body.paths,[{path:'/share/a'},{path:'/share/b'}]);
 assert.equal(many[0].body.recursive,false);
 const one = applyPlan({entries:[dir('/share/Public')],spec:parseOctal('0755'),recursive:true});
 assert.equal(one[0].endpoint,'api/jobs/chmod');
 assert.equal(one[0].body.recursive,true);
});

test('the three apply modes map onto the two masks (§1.2)', () => {
 const spec = parseOctal('0700');
 const of = apply => applyPlan({entries:[dir('/share/Public')],spec,recursive:true,apply,smartX:false})[0].body;
 const all = of('all');
 assert.deepEqual(all.files,{mask:0o7777,value:0o700});
 assert.deepEqual(all.dirs,{mask:0o7777,value:0o700});
 const files = of('files');
 assert.deepEqual(files.dirs,{mask:0,value:0});      // folders-only is a zero mask
 assert.deepEqual(files.files,{mask:0o7777,value:0o700});
 const dirs = of('dirs');
 assert.deepEqual(dirs.files,{mask:0,value:0});
 assert.deepEqual(dirs.dirs,{mask:0o7777,value:0o700});
});

test('smart X alone IS a request — no box has to be ticked for it', () => {
 // Turning on "recursive" and leaving the preset checked is the whole gesture
 // people make; an untouched grid must not make Apply a no-op.
 const plan = applyPlan({entries:[dir('/share/Public')],spec:EMPTY,recursive:true,smartX:true});
 assert.equal(plan.length,1);
 assert.deepEqual(plan[0].body.dirs,{mask:0o777,value:0o755});
 assert.deepEqual(plan[0].body.files,{mask:0o777,value:0o644});
 // …and with the preset off and nothing touched there is nothing to post.
 assert.deepEqual(applyPlan({entries:[dir('/share/Public')],spec:EMPTY,recursive:true,smartX:false}),[]);
 assert.deepEqual(applyPlan({entries:[file('/share/a')],spec:EMPTY}),[]);
});

test('the apply-to scope is "all" whenever the change is not recursive', () => {
 // A disabled radio keeps its dot: choosing "Folders only", un-ticking
 // Recursive and pressing Apply over a file selection posted files:{mask:0} and
 // came back "changed 0 of N, N skipped" for a change the user had watched
 // themselves make.
 assert.equal(applyScope(true,'dirs'),'dirs');
 assert.equal(applyScope(true,'files'),'files');
 assert.equal(applyScope(false,'dirs'),'all');
 assert.equal(applyScope(false,'files'),'all');
 assert.equal(applyScope(true,'nonsense'),'all');
 // And the rule holds at the wire, not only in the dialog: a non-recursive job
 // never zeroes either mask.
 const body = applyPlan({entries:[file('/share/a'),file('/share/b')],spec:parseOctal('0644'),recursive:false,apply:'dirs'})[0].body;
 assert.deepEqual(body.files,{mask:0o7777,value:0o644});
 assert.deepEqual(body.dirs,{mask:0o7777,value:0o644});
});

test('Apply is blocked by ONE rule, and an attempt never overrides it', () => {
 // paintWarnings disabled the button for a recursive special-bit SET and
 // applyNow's finally re-enabled it unconditionally, so a refused request left
 // the dialog offering to send it again under its own warning.
 const sets = jobSpecs({spec:toggleBit(EMPTY,SETUID,true),apply:'all',smartX:false});
 const clears = jobSpecs({spec:toggleBit(EMPTY,SETUID,false),apply:'all',smartX:false});
 assert.equal(applyBlocked({recursive:true,specs:sets}),'special');
 assert.equal(applyBlocked({recursive:true,specs:sets,applying:false}),'special'); // the end of an attempt does not clear it
 assert.equal(applyBlocked({recursive:true,specs:clears}),'');
 assert.equal(applyBlocked({recursive:false,specs:sets}),'');   // one item may set setuid
 assert.equal(applyBlocked({applying:true,recursive:false,specs:clears}),'applying');
 assert.equal(applyBlocked({canWrite:false,specs:clears}),'readOnly');
 assert.equal(applyBlocked(),'');
 // A field that is not a mode is a reason of its own, and it outranks the
 // recursive special-bit refusal: there is nothing to grade until it parses.
 assert.equal(applyBlocked({octalInvalid:true}),'octal');
 assert.equal(applyBlocked({octalInvalid:true,recursive:true,specs:sets}),'octal');
 assert.equal(applyBlocked({octalInvalid:true,canWrite:false}),'readOnly');
});

test('the octal field never stands for a PREFIX of what it is showing', () => {
 // Typing 0788 recorded the 0007 that parsed at "07" and Apply sent that while
 // the field read 0788; clearing the field left the previous spec standing
 // (round 1, finding 13). Three states, told apart explicitly.
 assert.deepEqual(octalState('0755'),{state:'valid',spec:parseOctal('0755')});
 assert.deepEqual(octalState(' 2755 '),{state:'valid',spec:parseOctal('2755')});
 // The keystrokes of 0788, one at a time: the last one is invalid and STAYS
 // invalid — it must never be read as the 07 before it.
 assert.equal(octalState('0').state,'valid');
 assert.equal(octalState('07').state,'valid');
 assert.equal(octalState('078').state,'invalid');
 assert.equal(octalState('0788').state,'invalid');
 assert.equal(octalState('0788').spec,null,'an invalid field carries no spec at all');
 assert.equal(applyBlocked({octalInvalid:octalState('0788').state === 'invalid'}),'octal');
 // An EMPTIED field is "unchanged/mixed", which is the spec the dialog opens
 // with — not the last thing that happened to parse.
 assert.deepEqual(octalState(''),{state:'empty',spec:EMPTY});
 assert.deepEqual(octalState('   '),{state:'empty',spec:EMPTY});
 assert.deepEqual(octalState(null),{state:'empty',spec:EMPTY});
 assert.deepEqual(applyPlan({entries:[file('/share/a')],spec:octalState('').spec}),[],'so Apply posts nothing for it');
 // Five digits, letters and a stray sign are not modes either.
 for (const bad of ['07777x','077777','-755','7 5 5']) assert.equal(octalState(bad).state,'invalid',bad);
 assert.match(OCTAL_REFUSAL,/four octal digits/);
});

test('smart X is ignored when the change is not recursive', () => {
 // The preset is about what is BELOW an item; applied to the item itself it
 // would silently overwrite the mode the user is looking at.
 const plan = applyPlan({entries:[dir('/a'),dir('/b')],spec:parseOctal('0700'),recursive:false,smartX:true});
 assert.deepEqual(plan[0].body.dirs,{mask:0o7777,value:0o700});
 assert.deepEqual(plan[0].body.files,{mask:0o7777,value:0o700});
});

test('crossMounts rides along on both job shapes, and never on the sync ones', () => {
 const job = applyPlan({entries:[dir('/share/Public')],spec:parseOctal('0755'),recursive:true,crossMounts:true});
 assert.equal(job[0].body.crossMounts,true);
 const sync = applyPlan({entries:[file('/share/a')],spec:parseOctal('0644'),crossMounts:true});
 assert.equal('crossMounts' in sync[0].body,false);
});

test('chown sends ONLY the half it changes — never a -1 on the wire (§11)', () => {
 // The routes read uid and gid as *int: absent is "leave this alone" and a
 // NEGATIVE number is refused outright (routes_perm.go chownIDs), so the
 // sentinel must never be spelled out.
 const owner = applyPlan({entries:[file('/share/a')],owner:1003});
 assert.equal(owner.length,1);
 assert.equal(owner[0].endpoint,'api/fs/chown');
 assert.deepEqual(owner[0].body,{path:'/share/a',uid:1003});
 assert.equal('gid' in owner[0].body,false);
 const group = applyPlan({entries:[file('/share/a')],group:100});
 assert.deepEqual(group[0].body,{path:'/share/a',gid:100});
 assert.equal('uid' in group[0].body,false);
 // uid 0 is root and is a real target: it must never be confused with "absent".
 const toRoot = applyPlan({entries:[file('/share/a')],owner:0,group:0});
 assert.deepEqual(toRoot[0].body,{path:'/share/a',uid:0,gid:0});
});

test('a recursive chown is the job route and omits the untouched half too', () => {
 const [request] = applyPlan({entries:[dir('/share/Public')],owner:1003,recursive:true,crossMounts:true});
 assert.equal(request.endpoint,'api/jobs/chown');
 assert.deepEqual(request.body,{paths:[{path:'/share/Public'}],uid:1003,recursive:true,crossMounts:true});
});

test('chown is posted BEFORE chmod, because a chown clears setuid (§3.2)', () => {
 const plan = applyPlan({entries:[file('/share/a')],spec:toggleBit(EMPTY,SETUID,true),owner:1003});
 assert.deepEqual(plan.map(r => r.op),['chown','chmod']);
 assert.equal(plan[0].endpoint,'api/fs/chown');
 assert.equal(plan[1].endpoint,'api/fs/chmod');
 assert.deepEqual(plan[1].body,{path:'/share/a',mask:SETUID,value:SETUID});
});

test('the ordering is JOBS too: the chmod waits for the chown to FINISH (§3.2)', () => {
 // Both halves of a multi-item or recursive apply are jobs, and a 202 only
 // means accepted — so the two used to walk the same tree at once in the
 // metadata pool and a 4755 could land with setuid cleared by the chown behind
 // it (round 1, finding 12). The dialog gates on the chown job's terminal state.
 const plan = applyPlan({entries:[file('/share/a'),file('/share/b')],spec:toggleBit(EMPTY,SETUID,true),owner:1003});
 assert.deepEqual(plan.map(r => r.op),['chown','chmod']);
 assert.ok(plan.every(r => r.job),'both halves are jobs here, which is why the gate is needed');
 assert.equal(chownGateMessage({state:'done'}),'','a finished chown lets the mode change go');
 // Anything short of done stops the chmod, and says which it was.
 assert.match(chownGateMessage({state:'failed'}),/^The change of owner failed, so the permissions were not changed\./);
 assert.match(chownGateMessage({state:'cancelled'}),/^The change of owner was cancelled, so the permissions were not changed\./);
 assert.match(chownGateMessage({state:'running'}),/ended running/);
 // A poll that gave up, or a 202 with no id at all, is not a terminal state
 // either — and guessing "it probably worked" is what the gate exists to refuse.
 assert.match(chownGateMessage(null),/could not be followed to the end/);
 assert.match(chownGateMessage(undefined),/could not be followed to the end/);
 for (const job of [null,{state:'failed'},{state:'cancelled'}]) {
  assert.match(chownGateMessage(job),/apply the permissions again/,'and it says what to do next');
 }
});

test('applyPlan refuses to invent work out of nothing', () => {
 assert.deepEqual(applyPlan({entries:[],spec:parseOctal('0755')}),[]);
 assert.deepEqual(applyPlan({entries:[null,undefined],spec:parseOctal('0755')}),[]);
 assert.deepEqual(applyPlan({}),[]);
});

// --- what the dialog says -----------------------------------------------------

test('permsApplies names the scale and says when the modes disagree', () => {
 assert.equal(permsApplies([dir('/share/Public')]),'1 folder — Public');
 assert.equal(permsApplies([file('/share/a.txt')]),'1 file — a.txt');
 assert.equal(permsApplies([dir('/a'),dir('/b'),file('/c')],[0o755,0o755,0o755]),'3 items — 2 folder(s), 1 file(s)');
 assert.match(permsApplies([dir('/a'),file('/c')],[0o755,0o644]),/mixed permissions$/);
 assert.equal(permsApplies([]),'Nothing selected.');
});

// A QTS share is a symlink: /share/Public → /share/CACHEDEV1_DATA/Public.
const share = (rest = {}) => ({
 path:'/share/Public',name:'Public',type:'symlink',mode:'0777',isSymlink:true,targetType:'dir',
 linkTarget:'CACHEDEV1_DATA/Public',linkResolved:'/share/CACHEDEV1_DATA/Public',...rest,
});

test('a recursive impact measures the share’s TARGET, not the one-file link', () => {
 // The recursive job changes the whole target tree; a size job pointed at the
 // link counts 1. Promising "1 item" before changing eight thousand is the bug.
 const {roots,unmeasured} = impactRoots([share()],{recursive:true});
 assert.deepEqual(roots,[{path:'/share/CACHEDEV1_DATA/Public',pathB64:undefined}]);
 assert.deepEqual(sizeRequest(roots),{paths:[{path:'/share/CACHEDEV1_DATA/Public'}]});
 assert.deepEqual(unmeasured,[]);
 // The authoritative bytes win when the target has them, as everywhere else.
 const bytes = impactRoots([share({linkResolvedB64:b64('/share/CACHEDEV1_DATA/\xffub')})],{recursive:true});
 assert.deepEqual(sizeRequest(bytes.roots),{paths:[{pathB64:b64('/share/CACHEDEV1_DATA/\xffub')}]});
});

test('a NON-recursive impact measures what was actually selected', () => {
 const {roots} = impactRoots([share()],{recursive:false});
 assert.deepEqual(sizeRequest(roots),{paths:[{path:'/share/Public'}]});
 // An ordinary folder is itself either way.
 assert.deepEqual(sizeRequest(impactRoots([dir('/share/Media')],{recursive:true}).roots),{paths:[{path:'/share/Media'}]});
});

test('a link that never resolved is said to be unmeasured, not counted as 1', () => {
 const broken = share({linkResolved:'',targetType:'dir'});
 const {roots,unmeasured} = impactRoots([broken,dir('/share/Media')],{recursive:true});
 assert.deepEqual(roots,[dir('/share/Media')]);
 assert.deepEqual(unmeasured,['Public']);
 assert.match(impactNote(unmeasured),/size of the linked folder was not measured for Public/);
 assert.equal(impactNote([]),'');
});

test('#pImpact reports the measurement, and says so while it is not one', () => {
 assert.equal(impactText({state:'done',result:{files:7204,dirs:837}}),
  `Will change ${(8041).toLocaleString()} items (${(7204).toLocaleString()} files, ${(837).toLocaleString()} folders).`);
 assert.equal(impactText({state:'running',text:'Measuring…'}),'Measuring…');
 assert.equal(impactText({state:'cancelled',text:'Measurement cancelled.'}),'Measurement cancelled.');
 assert.equal(impactText(null),'');
});

test('a diff is a WARNING with a line that stays, never a success (§3.3, §12)', () => {
 const clean = reportResult({before:{},entry:{},diffs:[]},{op:'chmod'});
 assert.deepEqual(clean,{warned:false,lines:[],tone:'none'});
 const dropped = reportResult({diffs:[{field:'setgid',want:'1',got:'0'}]},{op:'chmod',group:'team'});
 assert.equal(dropped.warned,true);
 assert.deepEqual(dropped.lines,['The setgid bit was not applied: you are not a member of group team.']);
 assert.equal(dropped.tone,'special');
 // showDiff toasts lines[0] and leaves the whole list on screen, so the first
 // line is the one that has to explain the rest.
 const chown = reportResult({diffs:[{field:'uid',want:'1003',got:'0'},{field:'setuid',want:'on',got:'off'}]},{op:'chown'});
 assert.equal(chown.lines.length,2);
 assert.match(chown.lines[0],/setuid bit was cleared/);
 // A 200 with warnings and no diffs is still a warning, not a success.
 assert.equal(reportResult({warnings:['x']},{op:'chmod'}).warned,true);
 assert.equal(reportResult(null,{op:'chmod'}).warned,false);
});

test('the server’s sentences are the ONLY ones displayed when it sent any', () => {
 // Both sides word the same fact differently, so concatenating and
 // de-duplicating by string equality showed it twice, in two voices — one of
 // them (the old mode sentence) blaming an ACL that had nothing to do with it.
 const res = {
  diffs:[{field:'mode',want:'2755',got:'0755'},{field:'setgid',want:'on',got:'off'}],
  warnings:['the setgid bit was not applied: you are not a member of group team'],
 };
 const out = reportResult(res,{op:'chmod',group:'team'});
 assert.deepEqual(out.lines,res.warnings);      // verbatim, and nothing else
 assert.equal(out.lines.length,1);
 assert.equal(out.tone,'special');              // the diffs still grade it
});

test('the 2755 case falls back to ONE client sentence, the setgid one, first', () => {
 // A 200 that carries diffs and no prose: better a sentence of ours than a
 // silent warning — but still one fact, said once, cause first.
 const out = reportResult({diffs:[{field:'mode',want:'2755',got:'0755'},{field:'setgid',want:'on',got:'off'}]},
  {op:'chmod',group:'team'});
 assert.deepEqual(out.lines,['The setgid bit was not applied: you are not a member of group team.']);
 assert.equal(out.tone,'special');
});

test('the aclmode groupmask case keeps the mode sentence, neutrally worded', () => {
 const out = reportResult({diffs:[{field:'mode',want:'0775',got:'0755'}]},{op:'chmod'});
 assert.deepEqual(out.lines,['The mode was set to 0755, not the 0775 that was asked for.']);
 assert.doesNotMatch(out.lines[0],/ACL/);
 assert.equal(out.tone,'mode');
});

test('a permissions job’s expander offers DETAILS, not "warnings" (§4.2, §12)', () => {
 // The list holds two opposite facts, so neither "warnings" nor "skipped
 // items" is true of all of it.
 assert.equal(warningsLabel({kind:'chmod',warningCount:7591}),`Show details (${(7591).toLocaleString()})`);
 assert.equal(warningsLabel({kind:'chown',warningCount:1}),'Show details (1)');
 assert.equal(warningsLabel({kind:'copy',warningCount:3}),'Show warnings (3)');
});

test('an `unchanged` line is a CHANGE that landed elsewhere, never a skip', () => {
 // The kernel dropping setgid on an entry it did change is not the same fact
 // as an entry the walk could not touch, and telling an operator the file was
 // untouched when its mode had just been rewritten is the failure here.
 const job = {kind:'chmod',warningCount:3};
 const mixed = [
  '/share/Public/a.sh: the setgid bit was not applied (unchanged)',
  '/share/Public/b.txt: permission denied (permission)',
  '/share/Public/link: symlinks are never followed (unsupported)',
 ];
 const lines = mixed.map(w => warningLine(job,w));
 assert.deepEqual(lines.map(l => l.kind),['unchanged','skipped','skipped']);
 assert.equal(lines[0].tag,'Changed, not as asked:');
 assert.equal(lines[1].tag,'Skipped:');
 assert.equal(lines[0].text,mixed[0]);              // the server's sentence, verbatim
 // Every line carries its distinction in WORDS: no colour-only signal (§4.1).
 for (const line of lines) assert.ok(line.tag);
 // A job of any other kind keeps one plain vocabulary and no tag at all.
 assert.deepEqual(warningLine({kind:'copy'},mixed[1]),{kind:'warning',tag:'',text:mixed[1]});
 assert.equal(warningCode('a: b (unchanged)'),'unchanged');
 assert.equal(warningCode('no code at all'),'');
 assert.equal(warningCode(null),'');
});

test('actionMessage explains `unsupported` without sounding like a refusal (§12)', () => {
 const msg = actionMessage({code:'unsupported'});
 assert.match(msg,/symbolic link has no permissions of its own/);
 assert.notEqual(msg,actionMessage({code:'permission'}));
});

// --- the id pickers never cross a session (§10) --------------------------------

test('an admin’s roster is never shown to the session that replaced them', async t => {
 // /api/ids is narrowed server-side: an admin gets the full local lists, a
 // non-admin only their own user and their own groups. A cache that outlived
 // the session undid exactly that — showSession replaces the session in place,
 // nothing tears this module down, and the next user's F9 would have painted
 // the previous user's roster.
 t.after(() => { clearIdCache(); update({session:null}); });
 clearIdCache();
 let roster = {users:[{name:'admin',id:0},{name:'backup',id:1003}],groups:[{name:'administrators',id:0}]};
 let calls = 0;
 t.mock.method(globalThis,'fetch',async url => {
  calls++;
  const kind = new URL(String(url),'http://nas/').searchParams.get('kind');
  return new Response(JSON.stringify({items:roster[kind],truncated:false}),{status:200});
 });
 update({session:{user:'admin',uid:0,admin:true}});
 const asAdmin = await loadIds();
 assert.deepEqual(asAdmin.users.map(u => u.name),['admin','backup']);
 assert.equal(calls,2);                       // users + groups
 // Within the same session the answer is reused, which is the point of a cache.
 assert.equal((await loadIds()).users.length,2);
 assert.equal(calls,2);
 // A different user in the same tab: the cache must not answer for them.
 roster = {users:[{name:'sveinung',id:1001}],groups:[{name:'users',id:100}]};
 update({session:{user:'sveinung',uid:1001,admin:false}});
 const asUser = await loadIds();
 assert.equal(calls,4);                       // asked again, not served from the cache
 assert.deepEqual(asUser.users.map(u => u.name),['sveinung']);
 assert.deepEqual(asUser.groups.map(g => g.name),['users']);
});

// --- the properties dialog ↔ the size job (§8.4) -------------------------------

test('sizeRequest is one path and the hero crossing question', () => {
 assert.deepEqual(sizeRequest(dir('/share/Public')),{paths:[{path:'/share/Public'}]});
 assert.deepEqual(sizeRequest([dir('/share/Public')],{crossMounts:true}),{paths:[{path:'/share/Public'}],crossMounts:true});
});

test('sizeReport says what the job said, and never guesses', () => {
 assert.equal(sizeReport(null).text,'Still measuring — see Operations.');
 assert.match(sizeReport({state:'cancelled'}).text,/Measurement cancelled\./);
 assert.equal(sizeReport({state:'failed',error:'nope'}).text,'nope');
 const done = sizeReport({state:'done',result:{bytes:1024,files:2,dirs:1}});
 assert.equal(done.state,'done');
 assert.equal(done.text,'1 KiB in 2 file(s) and 1 folder(s)');
});

// A runner with every DOM-touching collaborator injected: this is the wiring,
// with nothing but a mocked fetch underneath it.
function harness({poll} = {}) {
 const posts = [],cancelled = [],tracked = [],reports = [];
 const runner = createSizeRunner({
  report:r => reports.push(r),
  track:job => tracked.push(job),
  cancel:async id => { cancelled.push(id); },
  poll:poll || (async id => ({id,state:'done',result:{bytes:2048,files:3,dirs:2}})),
 });
 return {runner,posts,cancelled,tracked,reports};
}

const mockFetch = (t,posts,id = 's1') => t.mock.method(globalThis,'fetch',async (url,options) => {
 posts.push({url:String(url),body:options.body ? JSON.parse(options.body) : null,method:options.method});
 return new Response(JSON.stringify({job:{id,state:'queued'}}),{status:202});
});

test('opening the dialog on a folder SUBMITS the size job', async t => {
 const {runner,posts,tracked,reports} = harness();
 mockFetch(t,posts);
 await runner.start([dir('/share/Public')],{crossMounts:true});
 assert.equal(posts.length,1);
 assert.match(posts[0].url,/api\/jobs\/size$/);
 assert.equal(posts[0].method,'POST');
 assert.deepEqual(posts[0].body,{paths:[{path:'/share/Public'}],crossMounts:true});
 assert.equal(tracked.length,1);                     // it is visible in Operations like any job
 assert.equal(reports.at(0).state,'running');
 assert.equal(reports.at(-1).text,'2 KiB in 3 file(s) and 2 folder(s)');
 assert.equal(runner.jobId,null);                    // finished: nothing left to cancel
});

test('closing the dialog CANCELS the job it started', async t => {
 // A du over a multi-terabyte share must not outlive the dialog that asked.
 let release;
 const pending = new Promise(resolve => { release = resolve; });
 const {runner,posts,cancelled,reports} = harness({poll:() => pending});
 mockFetch(t,posts);
 const started = runner.start([dir('/share/Public')]);
 await new Promise(resolve => setTimeout(resolve,0));
 assert.equal(runner.jobId,'s1');
 runner.stop();                                      // the dialog's close event
 assert.deepEqual(cancelled,['s1']);
 assert.equal(runner.jobId,null);
 release({id:'s1',state:'cancelled'});
 assert.equal(await started,null);                   // abandoned: it reports nothing
 assert.equal(reports.filter(r => r.state === 'done').length,0);
});

test('Recount replaces the running measurement rather than racing it', async t => {
 let release;
 const first = new Promise(resolve => { release = resolve; });
 let calls = 0;
 const {runner,posts,cancelled,reports} = harness({
  poll:async id => { calls++; return calls === 1 ? first : {id,state:'done',result:{bytes:1,files:1,dirs:0}}; },
 });
 mockFetch(t,posts);
 const stale = runner.start([dir('/share/Public')]);
 await new Promise(resolve => setTimeout(resolve,0));
 const fresh = runner.start([dir('/share/Public')]);
 await fresh;
 assert.deepEqual(cancelled,['s1']);                 // the first job was stopped, not left walking
 assert.equal(posts.length,2);
 release({id:'s1',state:'done',result:{bytes:999,files:9,dirs:9}});
 await stale;
 // Only the second measurement may paint. The first one's answer is discarded
 // even though it arrived last.
 const done = reports.filter(r => r.state === 'done');
 assert.equal(done.length,1);
 assert.match(done[0].text,/1 B in 1 file\(s\)/);
});

test('a size job that cannot even be submitted reports the failure once', async t => {
 const {runner,reports} = harness();
 t.mock.method(globalThis,'fetch',async () => new Response(JSON.stringify({error:{code:'protected',message:'no'}}),{status:403}));
 assert.equal(await runner.start([dir('/etc')]),null);
 assert.equal(reports.at(-1).state,'failed');
 assert.equal(runner.jobId,null);
});

// --- the properties dialog's own rows (§3.6) ----------------------------------

test('owner and mode are shown as both the name and the number (§5.4)', () => {
 assert.equal(ownerText('backup',1003,'user'),'backup (uid 1003)');
 assert.equal(ownerText('',5000,'user'),'uid 5000');
 assert.equal(ownerText('team',100,'group'),'team (gid 100)');
 assert.equal(modeText({mode:'2755',modeStr:'drwxr-sr-x',type:'dir'}),'drwxr-sr-x  2755');
 assert.equal(modeText({mode:'0644',type:'file'}),'-rw-r--r--  0644');
});

test('flags are words, never colour alone (§4.1)', () => {
 assert.match(flagsText({class:'protected'},{}),/Protected system path/);
 assert.match(flagsText({mountPoint:true},{}),/Mount point/);
 assert.match(flagsText({},{readOnly:true}),/Read-only filesystem/);
 assert.equal(flagsText({},{}),'—');
});

test('propsSections carries the ACL sentence and hides the Link group for a file', () => {
 const sections = propsSections({
  entry:{...file('/share/Public/a.txt'),acl:'posix',nlink:1,mtime:'2026-09-13T10:00:00Z'},
  fs:{fsType:'ext4',mount:'/share/CACHEDEV1_DATA',readOnly:false,avail:1024,total:4096},
  acl:{backend:'posix',state:'posix'},
 });
 const [general,permissions,link] = sections;
 assert.equal(general.title,'General');
 assert.ok(general.rows.some(([label,,opts]) => label === 'Full path' && opts?.copy === '/share/Public/a.txt'));
 assert.ok(permissions.rows.some(([label,value]) => label === 'ACL' && /does not display/.test(value)));
 assert.equal(link.hidden,true);
});

test('propsSections shows a symlink’s target and says when it is broken', () => {
 const entry = {...file('/share/Public/link'),type:'symlink',isSymlink:true,linkTarget:'../gone'};
 const sections = propsSections({entry,fs:{},acl:{}});
 const link = sections.find(s => s.title === 'Link');
 assert.equal(link.hidden,false);
 assert.ok(link.rows.some(([label,value]) => label === 'Target' && value === '../gone'));
 assert.ok(link.rows.some(([,value]) => /Broken/.test(String(value))));
});

test('a trivial NFSv4 ACL is stated as harmless rather than badged', () => {
 const sections = propsSections({entry:{...file('/x'),acl:'nfs4-trivial'},fs:{},acl:{backend:'nfs4',state:'nfs4-trivial',aclmode:'discard',dataset:'tank/share'}});
 const permissions = sections.find(s => s.title === 'Permissions');
 const acl = permissions.rows.find(([label]) => label === 'ACL');
 assert.match(acl[1],/changing the mode is safe here/);
 assert.ok(permissions.rows.some(([label,value]) => label === 'ZFS aclmode' && /discard \(dataset tank\/share\)/.test(value)));
});
