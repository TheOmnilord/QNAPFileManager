// Run with: node --test internal/web/perm_test.mjs
//
// The JS mirror of internal/perm (M3 contract §1, §9, §15 "node"). Every case
// here has a twin in the Go tests: the arithmetic is authoritative in Go and
// this file is what proves the two agree. It is also the only part of M3 that
// is fully exercised on a Windows dev box (§14), so it carries more of the
// milestone's weight than a UI test usually does.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {
 ALL,PERM,SPECIAL,SETUID,SETGID,STICKY,BITS,SPECIAL_BITS,EMPTY,
 ACL_NFS4_TEXT,ACL_POSIX_TEXT,ACL_UNKNOWN_TEXT,SMART_DIRS,SMART_FILES,RECURSIVE_SPECIAL_REFUSAL,
 ID_INVALID,ID_MAX,
 aclBadge,applySpec,bitState,capsFor,diffText,diffTexts,diffTone,idItem,idItems,idLabel,idProblem,jobSpecs,
 modelOf,octal,octalField,parseId,parseOctal,permGrade,recursiveSetsSpecial,setsSpecial,specTouched,
 symbolic,symbolicField,toggleBit,
} from './static/js/perm.js';

// --- ModeSpec.Apply (§1.1) ----------------------------------------------------

test('applySpec is (cur &^ mask) | (value & mask), over every special bit', () => {
 const cases = [
  // [name, mask, value, cur, want]
  ['absolute set',ALL,0o755,0o644,0o755],
  ['absolute set clears setuid',ALL,0o755,0o4755,0o755],
  ['a zero mask changes nothing',0,0o777,0o600,0o600],
  ['one bit, on',0o020,0o020,0o644,0o664],
  ['one bit, off',0o020,0,0o664,0o644],
  ['setuid set',SETUID,SETUID,0o755,0o4755],
  ['setuid cleared',SETUID,0,0o4755,0o755],
  ['setgid set',SETGID,SETGID,0o755,0o2755],
  ['setgid cleared',SETGID,0,0o2755,0o755],
  ['sticky set',STICKY,STICKY,0o777,0o1777],
  ['sticky cleared',STICKY,0,0o1777,0o777],
  ['all three cleared at once',SPECIAL,0,0o7777,0o777],
  ['permission bits only leave special alone',PERM,0o750,0o4644,0o4750],
  ['everything',ALL,0o7777,0,0o7777],
 ];
 for (const [name,mask,value,cur,want] of cases) {
  assert.equal(applySpec({mask,value},cur),want,`${name}: ${octal(applySpec({mask,value},cur))} != ${octal(want)}`);
 }
});

test('applySpec never lets a bit outside 07777 escape', () => {
 // A mode from the wire could carry file-type bits; the spec is only ever the
 // permission half, and the result is masked the same way Go's uint32 & 07777 is.
 assert.equal(applySpec({mask:0o170777,value:0o170755},0o644),0o755);
 assert.equal(applySpec({mask:ALL,value:ALL},0o100644),0o7777);
});

test('setsSpecial is about SETTING, never clearing (§1.3)', () => {
 assert.equal(setsSpecial({mask:SETUID,value:SETUID}),true);
 assert.equal(setsSpecial({mask:SETGID,value:SETGID}),true);
 assert.equal(setsSpecial({mask:STICKY,value:STICKY}),true);
 // Clearing all three is exactly the cleanup a recursive chmod is allowed to do.
 assert.equal(setsSpecial({mask:SPECIAL,value:0}),false);
 assert.equal(setsSpecial({mask:ALL,value:0o755}),false);
 assert.equal(setsSpecial({mask:ALL,value:0o4755}),true);
 // A value bit outside the mask is not set by this spec at all.
 assert.equal(setsSpecial({mask:PERM,value:0o4755}),false);
 assert.equal(setsSpecial(EMPTY),false);
});

// --- symbolic and octal -------------------------------------------------------

test('symbolic renders the ls -l form, special bits included', () => {
 assert.equal(symbolic(0o755,true),'drwxr-xr-x');
 assert.equal(symbolic(0o644,false),'-rw-r--r--');
 assert.equal(symbolic(0o2755,true),'drwxr-sr-x');      // the contract's own example
 assert.equal(symbolic(0o4755,false),'-rwsr-xr-x');
 assert.equal(symbolic(0o4644,false),'-rwSr--r--');     // setuid without execute
 assert.equal(symbolic(0o2644,false),'-rw-r-Sr--');
 assert.equal(symbolic(0o1777,true),'drwxrwxrwt');      // /tmp
 assert.equal(symbolic(0o1666,false),'-rw-rw-rwT');
 assert.equal(symbolic(0,false),'----------');
 assert.equal(symbolic(0o7777,true),'drwsrwsrwt');
});

test('octal spells a mode exactly as perm.Octal does — four digits, zero padded', () => {
 // The worker's Diff carries Want and Got as perm.Octal strings, and the dialog
 // shows those beside its own. One spelling, or the user cannot compare them.
 assert.equal(octal(0o755),'0755');
 assert.equal(octal(0o2755),'2755');
 assert.equal(octal(0o7777),'7777');
 assert.equal(octal(0),'0000');
});

test('parseOctal takes what a person types and refuses what is not a mode', () => {
 assert.deepEqual(parseOctal('755'),{mask:ALL,value:0o755});
 assert.deepEqual(parseOctal('0755'),{mask:ALL,value:0o755});
 assert.deepEqual(parseOctal(' 02755 '),{mask:ALL,value:0o2755});
 assert.deepEqual(parseOctal('0o644'),{mask:ALL,value:0o644});
 assert.equal(parseOctal('758'),null);      // 8 is not an octal digit
 assert.equal(parseOctal('07777x'),null);
 assert.equal(parseOctal('077777'),null);   // five digits is not a mode
 assert.equal(parseOctal(''),null);
 assert.equal(parseOctal(null),null);
});

test('typing a mode is ABSOLUTE — the bits left out are cleared', () => {
 // This is why the octal field yields mask 07777 and not just the bits named:
 // "0755" on a setgid directory means the setgid bit goes.
 const spec = parseOctal('0755');
 assert.equal(applySpec(spec,0o2775),0o755);
});

// --- the grid over a selection (§1.1, mixed) -----------------------------------

const entry = (mode,rest = {}) => ({mode,name:'x',type:'file',...rest});

test('modelOf reads the modes the listing already carries', () => {
 assert.deepEqual(modelOf([entry('0755'),entry('0644')]).modes,[0o755,0o644]);
 assert.deepEqual(modelOf([{}]).modes,[0]);
 assert.deepEqual(modelOf(null).modes,[]);
});

test('bitState is three-valued: on, off, and mixed → indeterminate', () => {
 const model = modelOf([entry('0755'),entry('0644')]);
 assert.equal(bitState(0o400,model),true);   // both readable by owner
 assert.equal(bitState(0o100,model),null);   // 0755 executes, 0644 does not
 assert.equal(bitState(0o002,model),false);  // neither is world-writable
 assert.equal(bitState(SETUID,model),false);
 // An empty selection has nothing to be mixed about.
 assert.equal(bitState(0o400,{modes:[],spec:EMPTY}),false);
});

test('a touched bit stops being mixed, whichever way it was moved', () => {
 const model = modelOf([entry('0755'),entry('0644')]);
 const on = {...model,spec:toggleBit(model.spec,0o100,true)};
 assert.equal(bitState(0o100,on),true);
 assert.deepEqual(on.spec,{mask:0o100,value:0o100});
 const off = {...model,spec:toggleBit(on.spec,0o100,false)};
 assert.equal(bitState(0o100,off),false);
 assert.deepEqual(off.spec,{mask:0o100,value:0});   // still in the mask: it will be written
 assert.equal(specTouched(off.spec),true);
 assert.equal(specTouched(EMPTY),false);
});

test('only the touched bits are applied to a mixed selection', () => {
 const model = modelOf([entry('0755'),entry('0644')]);
 const spec = toggleBit(model.spec,0o020,true);     // group write, on
 assert.equal(applySpec(spec,0o755),0o775);
 assert.equal(applySpec(spec,0o644),0o664);         // the execute difference survives
});

test('the octal field is blank (placeholder "mixed") until the outcome agrees', () => {
 const mixed = modelOf([entry('0755'),entry('0644')]);
 assert.equal(octalField(mixed),'');
 assert.equal(symbolicField(mixed,false),'');
 // One entry always has a number.
 assert.equal(octalField(modelOf([entry('0755')])),'0755');
 assert.equal(symbolicField(modelOf([entry('0755')]),true),'drwxr-xr-x');
 // Typing an absolute mode makes the outcome the same for all of them, so the
 // field fills in — that is the point of the mask/value form.
 const set = {...mixed,spec:parseOctal('0644')};
 assert.equal(octalField(set),'0644');
 // A partial touch leaves them different, so it stays blank.
 const touched = {...mixed,spec:toggleBit(mixed.spec,0o020,true)};
 assert.equal(octalField(touched),'');
});

test('the grid and the special row cover 07777 exactly once', () => {
 const bits = [...BITS,...SPECIAL_BITS].map(b => b.bit);
 assert.equal(new Set(bits).size,12);
 assert.equal(bits.reduce((a,b) => a|b,0),ALL);
});

// --- smart X and the two job specs (§1.2) -------------------------------------

test('smart X is a client-side preset: 0755 for folders, 0644 for files', () => {
 const {files,dirs} = jobSpecs({spec:EMPTY,apply:'all',smartX:true});
 assert.deepEqual(dirs,SMART_DIRS);
 assert.deepEqual(files,SMART_FILES);
 assert.deepEqual(dirs,{mask:0o777,value:0o755});
 assert.deepEqual(files,{mask:0o777,value:0o644});
 // The preset's mask is 0777, so it never touches a special bit by itself: a
 // setgid directory keeps its setgid through a recursive smart-X.
 assert.equal(applySpec(dirs,0o2755),0o2755);
});

test('an absolute mode typed BEFORE smart X keeps its special-bit clears', () => {
 // "0777" means the special bits go; the preset then decides the rwx half, and
 // the clears — which the preset's 0777 mask cannot express — are merged back.
 const {dirs} = jobSpecs({spec:parseOctal('0777'),apply:'all',smartX:true});
 assert.equal(dirs.mask,ALL);
 assert.equal(dirs.value,0o755);
 assert.equal(applySpec(dirs,0o2755),0o755);
});

test('without smart X both halves carry the spec the user built', () => {
 const spec = parseOctal('0750');
 assert.deepEqual(jobSpecs({spec,apply:'all',smartX:false}),{files:spec,dirs:spec});
});

test('"files only" and "folders only" are a ZERO MASK on the other half (§1.2)', () => {
 const spec = parseOctal('0700');
 const filesOnly = jobSpecs({spec,apply:'files',smartX:false});
 assert.deepEqual(filesOnly.dirs,{mask:0,value:0});
 assert.deepEqual(filesOnly.files,spec);
 const dirsOnly = jobSpecs({spec,apply:'dirs',smartX:false});
 assert.deepEqual(dirsOnly.files,{mask:0,value:0});
 assert.deepEqual(dirsOnly.dirs,spec);
 // A zero mask really does change nothing.
 assert.equal(applySpec(filesOnly.dirs,0o755),0o755);
});

test('a special bit the user CLEARED survives the smart-X preset', () => {
 // Clearing setgid across a tree is the cleanup §1.3 keeps; the preset's 0777
 // mask cannot express it, so it is merged in.
 const spec = toggleBit(EMPTY,SETGID,false);
 const {files,dirs} = jobSpecs({spec,apply:'all',smartX:true});
 assert.equal(dirs.mask,0o777|SETGID);
 assert.equal(dirs.value,0o755);
 assert.equal(applySpec(dirs,0o2775),0o755);
 assert.equal(files.mask,0o777|SETGID);
 assert.equal(applySpec(files,0o2664),0o644);
 assert.equal(setsSpecial(dirs),false);
});

test('a special bit the user SET is carried into the job, not silently dropped', () => {
 // The server refuses it as bad_request (§1.3). This side must not edit the
 // request into something the user did not ask for — it refuses out loud.
 const spec = toggleBit(EMPTY,SETUID,true);
 const specs = jobSpecs({spec,apply:'all',smartX:true});
 assert.equal(setsSpecial(specs.files),true);
 assert.equal(recursiveSetsSpecial(specs),true);
 assert.match(RECURSIVE_SPECIAL_REFUSAL,/never set one/);
 // Folders-only still refuses, because the dirs half carries it.
 assert.equal(recursiveSetsSpecial(jobSpecs({spec,apply:'dirs',smartX:true})),true);
 // And the files half alone is clean once the dirs half is zeroed... only if
 // the SET bit went with it.
 assert.equal(recursiveSetsSpecial(jobSpecs({spec:toggleBit(EMPTY,SETUID,false),apply:'all',smartX:true})),false);
});

// --- capability hints (§5) ----------------------------------------------------

test('capsFor is the owner arithmetic, and it is only a hint', () => {
 const file = {uid:1003,gid:100,user:'backup'};
 const admin = capsFor(0,[0],true,file);
 assert.equal(admin.chmod,true); assert.equal(admin.chownUID,true);
 assert.equal(admin.chgrpTo,null);      // "any"
 assert.equal(admin.reason,'');
 const owner = capsFor(1003,[100,101],false,file);
 assert.equal(owner.chmod,true); assert.equal(owner.chownUID,false);
 assert.deepEqual(owner.chgrpTo,[100,101]);
 const other = capsFor(1001,[100],false,file);
 assert.equal(other.chmod,false);
 assert.deepEqual(other.chgrpTo,[]);
 assert.match(other.reason,/Owned by backup \(uid 1003\)/);
 assert.match(other.reason,/Only the owner or an administrator/);
 // An orphan uid resolves to no name, and the number is the answer.
 assert.match(capsFor(1001,[],false,{uid:5000}).reason,/uid 5000/);
});

// --- the ACL badge (§6.3) -----------------------------------------------------

test('the badge reports a STATE, and none/trivial say nothing', () => {
 assert.equal(aclBadge({acl:''}),null);            // never probed
 assert.equal(aclBadge({acl:'none'}),null);
 assert.equal(aclBadge({acl:'nfs4-trivial'}),null); // the mode already says it
 assert.equal(aclBadge({}),null);
 assert.equal(aclBadge(null),null);
});

test('badge text is per backend, verbatim from identity plan §4.4', () => {
 const posix = aclBadge({acl:'posix'});
 assert.equal(posix.state,'posix');
 assert.equal(posix.title,ACL_POSIX_TEXT);
 assert.match(posix.title,/editing it will not remove the ACL\.$/);
 const nfs4 = aclBadge({acl:'nfs4'});
 assert.equal(nfs4.title,ACL_NFS4_TEXT);
 assert.match(nfs4.title,/discard or reduce/);
 assert.match(nfs4.title,/cannot be undone from this app/);
 // unknown gets the NFSv4 text PLUS the sentence saying why it says no more —
 // a read or parse failure is pessimistic, never "none".
 const unknown = aclBadge({acl:'unknown'});
 assert.ok(unknown.title.startsWith(ACL_NFS4_TEXT));
 assert.match(unknown.title,/could not read the ACL to say more/);
 assert.equal(unknown.title,ACL_UNKNOWN_TEXT);
 // Every badge has a glyph and a spoken label, never colour alone (§4.1).
 for (const badge of [posix,nfs4,unknown]) { assert.ok(badge.glyph); assert.ok(badge.label); }
 assert.notEqual(posix.glyph,nfs4.glyph);
});

// --- the diff (§3) ------------------------------------------------------------

test('a dropped setgid on a chmod names the group, verbatim', () => {
 const line = diffText({field:'setgid',want:'1',got:'0'},{op:'chmod',group:'team'});
 assert.equal(line,'The setgid bit was not applied: you are not a member of group team.');
 // With no group name it still says something true rather than nothing.
 assert.match(diffText({field:'setgid'},{op:'chmod'}),/not a member of that group/);
});

test('a bit cleared BY A CHOWN says so in the kernel’s terms, not the group’s', () => {
 const setuid = diffText({field:'setuid',want:'1',got:'0'},{op:'chown'});
 assert.equal(setuid,'The setuid bit was cleared by the change of owner — the kernel does this, and it cannot be kept.');
 const setgid = diffText({field:'setgid',want:'1',got:'0'},{op:'chown'});
 assert.match(setgid,/cleared by the change of owner/);
 // The same field under a chmod means something else entirely.
 assert.notEqual(diffText({field:'setgid'},{op:'chmod',group:'team'}),setgid);
});

test('a mode that landed elsewhere reports both numbers, and blames nothing', () => {
 // The same diff arrives from a groupmask chmod, from a dropped setgid and
 // from an ACL the kernel reduced. Naming a cause here was wrong in two of the
 // three, and the one that knows is the server (or the special-bit line).
 const line = diffText({field:'mode',want:'0775',got:'0755'},{op:'chmod'});
 assert.equal(line,'The mode was set to 0755, not the 0775 that was asked for.');
 assert.doesNotMatch(line,/ACL/);
 assert.match(diffText({field:'uid',want:'1003',got:'0'},{op:'chown'}),/owner was not changed/);
 assert.match(diffText({field:'gid',want:'100',got:'0'},{op:'chown'}),/group was not changed/);
 assert.match(diffText({field:'mystery',want:'a',got:'b'}),/mystery: asked for a, got b\./);
 assert.match(diffText({}),/did not land exactly as asked/);
});

test('diffText reads the Go spelling of the fields as well as the JSON one', () => {
 assert.equal(diffText({Field:'setuid',Want:'1',Got:'0'},{op:'chown'}),
  diffText({field:'setuid',want:'1',got:'0'},{op:'chown'}));
});

test('the 2755 case leads with the setgid line and drops the mode line', () => {
 // The contract's own scenario: a non-member owner asks for 2755, the kernel
 // writes 0755 and drops setgid. DiffOf reports BOTH halves, and the mode half
 // is the consequence — leading with it said what happened and never why, and
 // saying both said one fact twice.
 const diffs = [{field:'mode',want:'2755',got:'0755'},{field:'setgid',want:'on',got:'off'}];
 const lines = diffTexts(diffs,{op:'chmod',group:'team'});
 assert.equal(lines.length,1);
 assert.equal(lines[0],'The setgid bit was not applied: you are not a member of group team.');
});

test('a mode diff with nothing to explain it keeps its line', () => {
 const diffs = [{field:'mode',want:'0775',got:'0755'}];
 assert.deepEqual(diffTexts(diffs,{op:'chmod'}),['The mode was set to 0755, not the 0775 that was asked for.']);
});

test('diffTexts keeps every line that is its own fact, cause first', () => {
 // Ordering is the whole contract with the caller: showDiff toasts lines[0]
 // and keeps the rest on screen, so the line that explains the others leads.
 const diffs = [{field:'uid',want:'1003',got:'0'},{field:'setuid',want:'on',got:'off'}];
 const lines = diffTexts(diffs,{op:'chown'});
 assert.equal(lines.length,2);
 assert.match(lines[0],/setuid bit was cleared/);   // the special bit leads
 assert.match(lines[1],/owner was not changed/);
 assert.deepEqual(diffTexts([],{}),[]);
 assert.equal(diffTexts(null,{}).length,0);
});

test('diffTone grades a list without deciding a word of it', () => {
 assert.equal(diffTone([{field:'mode'},{field:'setgid'}]),'special');
 assert.equal(diffTone([{field:'mode'}]),'mode');
 assert.equal(diffTone([{field:'uid'}]),'mode');
 assert.equal(diffTone([]),'none');
 assert.equal(diffTone(null),'none');
});

// --- the ladder, as far as this side presents it (§7) -------------------------

test('permGrade defers to the server whenever the server says', () => {
 // The grade travels BESIDE the token in the 409 envelope (confirm.grade),
 // where routes_mutate.go writeConfirmRequiredGraded puts it.
 assert.equal(permGrade({grade:1,summary:{warnings:['the ACL will be destroyed and cannot be restored']}}),1);
 assert.equal(permGrade({grade:2,summary:{warnings:[]}}),2);
 assert.equal(permGrade({grade:0,summary:{warnings:['this cannot be undone']}}),2); // omitted: grade it here
 assert.equal(permGrade({summary:{grade:2,warnings:[]}}),2);                        // tolerated inside the summary too
});

test('permGrade fails towards the typed phrase', () => {
 assert.equal(permGrade({summary:{warnings:['the mode’s group bits become the ACL mask']}}),1);
 assert.equal(permGrade({summary:{warnings:['the ACL will be destroyed and cannot be restored from this app']}}),2);
 assert.equal(permGrade({summary:{warnings:['this cannot be undone']}}),2);
 assert.equal(permGrade({summary:{files:8003},recursive:true}),2);   // > 500 items
 assert.equal(permGrade({summary:{files:12},recursive:true}),1);
 assert.equal(permGrade({summary:{},protectedPath:true}),2);
 assert.equal(permGrade({}),1);                                      // a challenge is at least L1
});

// --- the id pickers (§10) -----------------------------------------------------

test('idItem tolerates the uid/gid spellings and refuses a row with no number', () => {
 assert.deepEqual(idItem({id:0,name:'admin'}),{id:0,name:'admin'});
 assert.deepEqual(idItem({uid:1003,user:'backup'}),{id:1003,name:'backup'});
 assert.deepEqual(idItem({gid:100,group:'users'}),{id:100,name:'users'});
 assert.deepEqual(idItem({id:5000}),{id:5000,name:''});
 assert.equal(idItem({name:'nobody'}),null);
 assert.equal(idItem(null),null);
 assert.deepEqual(idItems([{id:1},null,{name:'x'}]),[{id:1,name:''}]);
 assert.deepEqual(idItems('not a list'),[]);
});

test('idLabel shows the name AND the number, or just the number (§5.4)', () => {
 assert.equal(idLabel({id:0,name:'admin'},'user'),'admin (uid 0)');
 assert.equal(idLabel({id:100,name:'users'},'group'),'users (gid 100)');
 assert.equal(idLabel({id:5000,name:''},'user'),'uid 5000');
 assert.equal(idLabel(null),'');
});

test('parseId accepts a typed numeric id and nothing else', () => {
 assert.equal(parseId('1003'),1003);
 assert.equal(parseId(' 0 '),0);
 assert.equal(parseId('backup'),null);
 assert.equal(parseId('-1'),null);       // the routes refuse a negative id outright
 assert.equal(parseId(''),null);
 assert.equal(parseId('1.5'),null);
});

test('parseId is bounded by uid_t, both edges', () => {
 // uid_t is 32 bits unsigned and its top value IS (uid_t)-1, the kernel's own
 // "leave this alone", so the last id that names an account is one below it.
 assert.equal(ID_MAX,4294967294);
 assert.equal(parseId('4294967293'),4294967293);
 assert.equal(parseId(String(ID_MAX)),ID_MAX);
 assert.equal(parseId('4294967295'),null);    // (uid_t)-1: the sentinel, not an account
 assert.equal(parseId('9999999999'),null);    // ten digits, and far past the bound
});

test('idProblem makes an unreadable id an error, not a silent no-op', () => {
 // applyPlan reads null as "this half is not changing", so a ticked box with a
 // typo in it would otherwise apply nothing and report success.
 assert.equal(idProblem(true,'1003'),'');
 assert.equal(idProblem(true,'backup'),ID_INVALID);
 assert.equal(idProblem(true,'4294967295'),ID_INVALID);
 assert.equal(idProblem(true,''),ID_INVALID);
 assert.equal(idProblem(false,'nonsense'),'');   // the box is not ticked: not a problem
 assert.match(ID_INVALID,/Not a valid user or group id/);
});
