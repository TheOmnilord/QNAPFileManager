// Run with: node --test internal/web/transfer_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {transferTitle,clipboardToast,isInside,destinationInvalid,destinationRef,pathBytes,okEnabled,submissionLive,clipboardAfterPaste,publishMarking,transferSummary,transferGrade,transferErrorMessage,CROSS_DEVICE_MARK,TRANSFER_NOTICES} from './static/js/transfer.js';
import {ancestorChain} from './static/js/tree.js';

// Counts are grouped with toLocaleString, whose separator is the viewer's, so
// the expectations are built the same way rather than pinning one locale.
const n = value => value.toLocaleString();

test('transferTitle says which verb and how many', () => {
 assert.equal(transferTitle('copy',1),'Copy 1 item(s) to…');
 assert.equal(transferTitle('move',3),'Move 3 item(s) to…');
 assert.equal(transferTitle('copy',1204),`Copy ${n(1204)} item(s) to…`);
});

test('clipboardToast names the gesture that finishes the job', () => {
 assert.equal(clipboardToast('copy',2),'2 item(s) marked to copy — press Ctrl+V in the destination folder');
 assert.equal(clipboardToast('move',1),'1 item(s) marked to move — press Ctrl+V in the destination folder');
});

test('isInside respects path boundaries, never a bare prefix', () => {
 assert.equal(isInside('/a/b','/a'),true);
 assert.equal(isInside('/ab','/a'),false);   // the bug this test exists for
 assert.equal(isInside('/a','/a'),false);    // equal is not inside
 assert.equal(isInside('/a/b/c','/a'),true);
 assert.equal(isInside('/a/','/a'),false);   // a trailing slash is the same path
 assert.equal(isInside('/anything','/'),true);
 assert.equal(isInside('/','/'),false);
 assert.equal(isInside('share/x','/share'),false); // relative is never inside
});

const dir = path => ({path,name:path.split('/').pop(),type:'dir'});
const file = path => ({path,name:path.split('/').pop(),type:'file'});

test('destinationInvalid refuses a folder into itself, or into its own subtree', () => {
 const picked=[dir('/share/Public')];
 assert.equal(destinationInvalid('/share/Public',picked),true);       // itself
 assert.equal(destinationInvalid('/share/Public/',picked),true);      // same, spelled with a slash
 assert.equal(destinationInvalid('/share/Public/Sub',picked),true);   // inside itself
 assert.equal(destinationInvalid('/share/PublicOther',picked),false); // only shares a prefix
 assert.equal(destinationInvalid('/share/Media',picked),false);
});

test('destinationInvalid refuses a selected FILE as the destination but not its lookalike subtree', () => {
 // A file cannot be a destination folder; but nothing is "inside" a file, so a
 // path that merely starts with its name is fine (the server decides the rest).
 const picked=[file('/share/Public/notes.txt')];
 assert.equal(destinationInvalid('/share/Public/notes.txt',picked),true);
 assert.equal(destinationInvalid('/share/Public/notes.txt.d',picked),false);
 assert.equal(destinationInvalid('/share/Public',picked),false);
});

test('destinationInvalid keeps OK disabled until a real absolute path is set', () => {
 assert.equal(destinationInvalid('',[dir('/share/Public')]),true);
 assert.equal(destinationInvalid('  ',[dir('/share/Public')]),true);
 assert.equal(destinationInvalid('share/Public',[dir('/share/Public')]),true); // relative
 assert.equal(destinationInvalid('/share/Media',[]),false);
});

test('destinationInvalid checks EVERY selected item, not just the first', () => {
 const picked=[dir('/share/A'),dir('/share/B'),file('/share/c.txt')];
 assert.equal(destinationInvalid('/share/B/inner',picked),true);
 assert.equal(destinationInvalid('/share/c.txt',picked),true);
 assert.equal(destinationInvalid('/share/D',picked),false);
});

// b64 is the byte-safe encoding the server uses for pathB64: base64url of the
// RAW bytes, so a path that is not valid UTF-8 survives the trip.
const b64 = bytes => Buffer.from(bytes,'binary').toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const byteDir = bytes => ({path:'/src/�',pathB64:b64(bytes),name:'?',type:'dir'});

test('pathBytes prefers the filesystem bytes and says nothing it cannot know', () => {
 assert.equal(pathBytes({pathB64:b64('/src/\xff')}),'/src/\xff');
 assert.equal(pathBytes({path:'/share/Public'}),'/share/Public');
 assert.equal(pathBytes({path:'/share/æ'}),'/share/\xc3\xa6'); // a typed path is UTF-8
 assert.equal(pathBytes({pathB64:'not base64!!'}),null);
 assert.equal(pathBytes({path:''}),null);
 assert.equal(pathBytes(null),null);
});

test('destinationInvalid compares bytes, so two folders that LOOK alike are not one', () => {
 // "/src/\xff" and "/src/\xfe" both display as "/src/�". Comparing the
 // display text called them the same folder and disabled OK for good.
 const source=byteDir('/src/\xff');
 const target={path:'/src/�',pathB64:b64('/src/\xfe')};
 assert.equal(destinationInvalid(target,[source]),false);
 // The same bytes ARE the same folder, however they are spelled for the eye.
 assert.equal(destinationInvalid({path:'something else entirely',pathB64:b64('/src/\xff')},[source]),true);
 // And containment is a byte-boundary test too.
 assert.equal(destinationInvalid({path:'x',pathB64:b64('/src/\xff/sub')},[source]),true);
 assert.equal(destinationInvalid({path:'x',pathB64:b64('/src/\xffsibling')},[source]),false);
});

test('destinationInvalid bridges a typed path and a byte reference through UTF-8', () => {
 const source={path:'/share/æ',pathB64:b64('/share/\xc3\xa6'),name:'æ',type:'dir'};
 assert.equal(destinationInvalid('/share/æ',[source]),true);       // typed, same bytes
 assert.equal(destinationInvalid('/share/æ/sub',[source]),true);
 assert.equal(destinationInvalid('/share/ø',[source]),false);
});

test('destinationInvalid abstains rather than locking the button on an unanswerable question', () => {
 // The server re-checks every transfer; a comparison this side cannot make must
 // never be the thing that refuses. Only "unset or relative" still refuses.
 const undecodable={path:'/src/�',pathB64:'not base64!!',name:'?',type:'dir'};
 assert.equal(destinationInvalid({path:'/src/x',pathB64:b64('/src/x')},[undecodable]),false);
 assert.equal(destinationInvalid({pathB64:'not base64!!'},[{path:'/a',type:'dir'}]),false);
 // A reference from the server needs no absolute-path check of its own.
 assert.equal(destinationInvalid({pathB64:b64('/src/\xff')},[]),false);
 assert.equal(destinationInvalid('',[]),true);
 assert.equal(destinationInvalid('share/x',[]),true);
});

test('publishMarking lets the newer gesture win, however slowly the older resolves', () => {
 // Ctrl+X over unloaded rows starts fetching pages; the user then selects a
 // loaded item and presses Ctrl+C. The Ctrl+C bumped the counter, so when the
 // older move marking finally resolves it publishes nothing — it used to win by
 // finishing last, and Ctrl+V then moved the wrong items.
 const older=1,newer=2;                       // ++markGeneration for each gesture
 assert.equal(publishMarking(older,newer),false); // the stale Ctrl+X: discarded
 assert.equal(publishMarking(newer,newer),true);  // the Ctrl+C the user meant
 // A lone marking with nothing after it always publishes.
 assert.equal(publishMarking(1,1),true);
});

test('a paste spends the marking it opened with, not the one marked since', () => {
 // The race: A is marked; a Ctrl+C of B starts and is still fetching unloaded
 // listing pages; A is pasted, so the dialog holds A's entries; B's marking then
 // completes while the dialog is open; the paste is submitted. Reading the
 // clipboard at SUBMIT time captured B, and A's success cleared it. The dialog
 // records what it consumed when it opened, so B survives.
 const A={mode:'copy',entries:[{path:'/a'}]},B={mode:'move',entries:[{path:'/b'}]};
 const dialog={entries:A.entries,consumed:A};        // openTransfer({consumed:board})
 let clipboard=A;
 clipboard=B;                                        // B's Ctrl+C lands mid-dialog
 clipboard=clipboardAfterPaste(clipboard,dialog.consumed); // the paste is accepted
 assert.equal(clipboard,B);
 // And the ordinary case still empties the clipboard it actually used.
 const plain={entries:A.entries,consumed:A};
 assert.equal(clipboardAfterPaste(A,plain.consumed),null);
});

test('clipboardAfterPaste clears only the marking the paste actually spent', () => {
 const marked={mode:'copy',entries:[{path:'/a'}]};
 assert.equal(clipboardAfterPaste(marked,marked),null);
 // Dismissed paste, new marking made since, late 202 arrives: keep the new one.
 const newer={mode:'move',entries:[{path:'/b'}]};
 assert.equal(clipboardAfterPaste(newer,marked),newer);
 // An equal-looking but different object is still not the one that was spent.
 assert.equal(clipboardAfterPaste({mode:'copy',entries:[{path:'/a'}]},marked).mode,'copy');
 // Not a paste at all: the clipboard is none of this submission's business.
 assert.equal(clipboardAfterPaste(marked,null),marked);
 assert.equal(clipboardAfterPaste(null,null),null);
});

test('transferSummary is the facts and the reasons, separately', () => {
 const out=transferSummary({files:1204,bytes:8.2*1024**3,warnings:['a','b']});
 assert.equal(out.body,`${n(1204)} item(s), 8.2 GiB`);
 assert.equal(out.why,'a · b');
});

test('transferSummary does not invent a total the scan never measured', () => {
 // A capped pre-scan reports -1 (design §3): say the count, drop the size.
 assert.equal(transferSummary({files:500000,bytes:-1}).body,`${n(500000)} item(s)`);
 assert.equal(transferSummary({files:-1,bytes:-1}).body,'a set of items whose total size could not be measured');
 assert.equal(transferSummary({}).why,'');
 assert.equal(transferSummary(null).why,'');
});

// The exact sentences internal/web/routes_transfer.go writes about the
// operation. Grade 1 every one of them: they are loud, not dangerous.
const EXDEV=`Public and Media ${CROSS_DEVICE_MARK} 41.2 GB and then deletes the source instead of an instant rename; it can be cancelled, and a cancelled move leaves both copies.`;

test('transferGrade keeps the route own notices at a plain confirm', () => {
 assert.equal(transferGrade({warnings:[EXDEV]}),1);
 for (const notice of TRANSFER_NOTICES) assert.equal(transferGrade({warnings:[notice]}),1,notice);
 assert.equal(transferGrade({warnings:[...TRANSFER_NOTICES,EXDEV]}),1);
 assert.equal(transferGrade({warnings:[]}),1);
 assert.equal(transferGrade({}),1);
 assert.equal(transferGrade(null),1);
});

test('transferGrade promotes a guard reason to the typed phrase', () => {
 const guard='this is a QNAP system directory; changing it can break the NAS';
 assert.equal(transferGrade({warnings:[guard]}),2);
 // One protection reason among the route's own notices still counts.
 assert.equal(transferGrade({warnings:[EXDEV,'Existing files may be overwritten by this operation.',guard]}),2);
});

test('the pinned route notices are the whole set routes_transfer.go can write', () => {
 // A pin, not a tautology: if the Go text changes, this list must change with
 // it or an overwrite starts demanding a typed folder name (contract §1.12).
 assert.deepEqual(TRANSFER_NOTICES,[
  'The size could not be fully measured; the totals shown are a minimum.',
  'The sizes exceed what can be counted; the totals shown are a minimum.',
  'We could not tell whether this move crosses volumes; it may need to copy and then delete the source.',
  'Existing files may be overwritten by this operation.',
 ]);
 assert.equal(CROSS_DEVICE_MARK,'are on different volumes, so this move copies');
});

test('destinationRef sends a picked folder by reference, whatever the field shows', () => {
 // Possession, not resemblance. The field is a lossy view of the name — an
 // <input> strips CR/LF on assignment, and a non-UTF-8 name arrives with
 // replacement characters — so a text comparison could never hold for
 // "/share/photos\n" and used to fall back to a DIFFERENT, existing directory.
 const picked={path:'/share/photos\n',pathB64:'L3NoYXJlL3Bob3Rvcwo'};
 assert.deepEqual(destinationRef(picked,'/share/photos'),{pathB64:'L3NoYXJlL3Bob3Rvcwo'});
 assert.deepEqual(destinationRef(picked,''),{pathB64:'L3NoYXJlL3Bob3Rvcwo'});
 const lossy={path:'/share/Bilder – 2024 ?',pathB64:'L3NoYXJlL0JpbGRlcg'};
 assert.deepEqual(destinationRef(lossy,'anything at all'),{pathB64:'L3NoYXJlL0JpbGRlcg'});
 // A pick with no byte spelling still travels as its own path, not the field's.
 assert.deepEqual(destinationRef({path:'/share/photos '},'/share/photos'),{path:'/share/photos '});
});

test('destinationRef sends a typed path exactly as typed', () => {
 // No pick: the text is the authority, and it is UTF-8 by construction.
 // "/share/photos " (trailing space) is a legal Linux directory and is NOT
 // "/share/photos", so nothing is trimmed.
 assert.deepEqual(destinationRef(null,'/share/photos '),{path:'/share/photos '});
 assert.deepEqual(destinationRef(null,' /share/photos'),{path:' /share/photos'});
 // Except a single trailing newline, which is paste debris and never a name.
 assert.deepEqual(destinationRef(null,'/share/photos\n'),{path:'/share/photos'});
});

test('submissionLive lets a user walk away from a 30-second pre-flight', () => {
 // Same dialog, still open: the submission still owns it.
 assert.equal(submissionLive({started:3,current:3,open:true}),true);
 // Dismissed: no confirmation may be raised, no banner written.
 assert.equal(submissionLive({started:3,current:3,open:false}),false);
 // Reopened as a different transfer: a late response must not close THAT one.
 assert.equal(submissionLive({started:3,current:4,open:true}),false);
 assert.equal(submissionLive({started:3,current:4,open:false}),false);
});

test('isInside and destinationInvalid treat a trailing space as part of the name', () => {
 assert.equal(isInside('/share/photos /a','/share/photos '),true);
 assert.equal(isInside('/share/photos/a','/share/photos '),false);
 const picked=[{path:'/share/photos ',name:'photos ',type:'dir'}];
 assert.equal(destinationInvalid('/share/photos ',picked),true);   // itself
 assert.equal(destinationInvalid('/share/photos',picked),false);   // a different folder
});

test('okEnabled locks out a second submission while one is in flight', () => {
 const entries=[{path:'/share/A',name:'A',type:'dir'}];
 assert.equal(okEnabled({dest:'/share/B',entries,pending:false}),true);
 assert.equal(okEnabled({dest:'/share/B',entries,pending:true}),false);  // the duplicate-copy bug
 assert.equal(okEnabled({dest:'/share/A',entries,pending:false}),false); // still gated on the destination
 assert.equal(okEnabled({dest:'',entries,pending:false}),false);
});

test('editing the field is what gives up the pick', () => {
 // The dialog clears `picked` on the input event, so by the time the user has
 // typed something else there is no reference left to prefer — which is how a
 // typed path stays its own authority.
 assert.deepEqual(destinationRef(null,'/share/Media'),{path:'/share/Media'});
 assert.deepEqual(destinationRef(null,'/share/Public/Sub'),{path:'/share/Public/Sub'});
 assert.deepEqual(destinationRef(null,''),{path:''});
 assert.deepEqual(destinationRef(undefined,undefined),{path:''});
 // A pick with an empty byte spelling falls back to its own path, not the field.
 assert.deepEqual(destinationRef({path:'/share/Public',pathB64:''},'/typed'),{path:'/share/Public'});
});

test('transferErrorMessage says the refusals as the action the user took', () => {
 assert.equal(transferErrorMessage({code:'exists'},'move'),'The item is already in that folder.');
 assert.equal(transferErrorMessage({code:'invalid_target'},'move'),'The destination is inside the folder being moved.');
 assert.equal(transferErrorMessage({code:'invalid_target'},'copy'),'The destination is inside the folder being copied.');
 // Everything else is the shared table, unchanged.
 assert.match(transferErrorMessage({code:'exists'},'copy'),/already exists here/);
 assert.match(transferErrorMessage({code:'cross_device'},'move'),/different volumes/);
 assert.match(transferErrorMessage({code:'read_only'},'copy'),/Read-only mode is on/);
 assert.equal(transferErrorMessage({message:'boom'},'copy'),'boom');
});

test('ancestorChain is the folders a picker has to open, in order', () => {
 assert.deepEqual(ancestorChain('/share/Public/Docs'),['/share','/share/Public','/share/Public/Docs']);
 assert.deepEqual(ancestorChain('/'),[]);
 assert.deepEqual(ancestorChain(''),[]);
 assert.deepEqual(ancestorChain('share/Public'),[]); // relative: nothing to open
 assert.deepEqual(ancestorChain('/share//Public'),['/share','/share/Public']);
});
