// Run with: node --test internal/web/why_test.mjs
//
// The golden table of M4 contract §7.3: every mutating control against every
// cause, asserting a non-empty, non-duplicated sentence. The M3 precedent
// stands — a table is cheaper than finding the gap a fourth time.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {
 ACTIONS, CAUSES, DISABLING, GUARD_SENTENCE, KIND_SENTENCES, PAUSED_SENTENCE,
 READONLY_SENTENCE, SELECT_SENTENCE, capsSentence, entryKind, reasonsFor, whyDisabled,
} from './static/js/why.js';

const names = Object.keys(ACTIONS);
// A file owned by somebody else, which is what makes capsFor produce a reason.
const foreign = {uid: 1003, user: 'backup', mode: '0644', type: 'file'};
const me = {user: 'sveinung', uid: 1000, groups: [100], rootMode: false};

// allowedCtx is the context in which an action has nothing standing in its way:
// a session that may write, the listing on screen, one plain file selected.
const allowedCtx = () => ({readOnly: false, paused: false, count: 1, one: true, kind: 'file', session: me, entry: null});

test('every action is allowed, with its own title, when nothing is in the way', () => {
 for (const name of names) {
  const verdict = whyDisabled(name, allowedCtx());
  assert.equal(verdict.allowed, true, name);
  assert.equal(verdict.cause, '', name);
  assert.equal(verdict.sentence, ACTIONS[name].enabled, name);
  assert.ok(verdict.sentence.length > 0, name);
 }
});

test('every action × every cause yields a non-empty, non-duplicated sentence', () => {
 // The four causes, expressed as the context that produces each one.
 const contexts = {
  readonly: () => ({...allowedCtx(), readOnly: true}),
  selection: () => ({...allowedCtx(), count: 0, one: false}),
  capability: () => ({...allowedCtx(), entry: foreign, caps: {reason: 'Owned by backup (uid 1003). Only the owner or an administrator can change permissions.'}}),
  guard: () => ({...allowedCtx(), guard: {denied: true, reason: 'This is a protected system path and cannot be changed here.'}}),
 };
 for (const name of names) {
  const seen = new Map();
  for (const cause of CAUSES) {
   const spec = ACTIONS[name];
   // Read-only does not apply to an action that changes nothing, and a
   // selection reason does not apply to an action that acts on the FOLDER.
   // Both are facts about the table, not gaps in it.
   if (cause === 'readonly' && !spec.mutating) continue;
   if (cause === 'selection' && spec.needs === 'none') continue;
   const verdict = whyDisabled(name, contexts[cause]());
   assert.equal(verdict.cause, cause, `${name} × ${cause}`);
   assert.ok(verdict.sentence && verdict.sentence.trim().length > 0, `${name} × ${cause} has a sentence`);
   assert.ok(!seen.has(verdict.sentence), `${name}: ${cause} duplicates ${seen.get(verdict.sentence)}`);
   seen.set(verdict.sentence, cause);
   // Only the certain causes take the control away.
   assert.equal(verdict.allowed, !DISABLING.has(cause), `${name} × ${cause} enablement`);
  }
 }
});

test('a capability-only reason leaves the control ENABLED with the explanation (INV-2)', () => {
 const verdict = whyDisabled('permissions', {...allowedCtx(), entry: foreign});
 assert.equal(verdict.allowed, true, 'the kernel decides; the arithmetic only predicts');
 assert.equal(verdict.cause, 'capability');
 assert.match(verdict.sentence, /^Owned by backup \(uid 1003\)\./);
 assert.match(verdict.sentence, /Only the owner or an administrator can change permissions\./);
 assert.match(verdict.sentence, /You are signed in as sveinung\.$/);
});

test('an entry the signed-in user owns produces no capability reason at all', () => {
 const mine = {uid: 1000, user: 'sveinung', type: 'file'};
 const verdict = whyDisabled('permissions', {...allowedCtx(), entry: mine});
 assert.equal(verdict.cause, '');
 assert.equal(capsSentence(me, mine, null), '');
});

test('precedence: read-only outranks selection, selection outranks capability', () => {
 const everything = {
  ...allowedCtx(), readOnly: true, count: 0, one: false, entry: foreign,
  guard: {denied: true, reason: 'protected'},
 };
 assert.equal(whyDisabled('permissions', everything).cause, 'readonly');
 assert.equal(whyDisabled('permissions', {...everything, readOnly: false}).cause, 'selection');
 // Capability never outranks a guard denial, because capability does not
 // disable and guard does: reporting the hint there would leave a
 // guard-denied control enabled.
 const guarded = {...allowedCtx(), entry: foreign, guard: {denied: true, reason: 'protected'}};
 const verdict = whyDisabled('permissions', guarded);
 assert.equal(verdict.allowed, false);
 assert.equal(verdict.cause, 'guard');
 assert.deepEqual(verdict.causes, ['capability', 'guard'], 'both are reported, in precedence order');
});

test('the paused listing is a SELECTION reason with its own sentence, never read-only', () => {
 const verdict = whyDisabled('delete', {...allowedCtx(), paused: true});
 assert.equal(verdict.cause, 'selection');
 assert.equal(verdict.sentence, PAUSED_SENTENCE);
 assert.notEqual(verdict.sentence, READONLY_SENTENCE, 'a user would go and check Settings for nothing');
});

test('a non-mutating action is never refused for read-only mode', () => {
 for (const name of names.filter(n => !ACTIONS[n].mutating)) {
  const verdict = whyDisabled(name, {...allowedCtx(), readOnly: true});
  assert.notEqual(verdict.cause, 'readonly', name);
 }
});

test('one selected item is not the same as one TARGET item (round-3 finding 7)', () => {
 // Ctrl+Arrow: one row selected, focus somewhere else.
 const verdict = whyDisabled('rename', {...allowedCtx(), count: 1, one: false});
 assert.equal(verdict.allowed, false);
 assert.equal(verdict.sentence, 'Select one item to rename.');
});

test('too many selected items refuse a single-item action by name', () => {
 assert.equal(whyDisabled('rename', {...allowedCtx(), count: 4, one: false}).sentence, 'Select one item to rename.');
 assert.equal(whyDisabled('properties', {...allowedCtx(), count: 4, one: false}).sentence, 'Select one item to inspect.');
 // A multi-item action is happy with four.
 assert.equal(whyDisabled('delete', {...allowedCtx(), count: 4, one: false}).allowed, true);
});

test('nothing selected says so once, in the same words, for every action that needs a selection', () => {
 for (const name of names.filter(n => ACTIONS[n].needs !== 'none')) {
  const verdict = whyDisabled(name, {...allowedCtx(), count: 0, one: false});
  assert.equal(verdict.allowed, false, name);
  assert.equal(verdict.sentence, ACTIONS[name].selectionEmpty || SELECT_SENTENCE, name);
 }
 // …and the two Trash actions have their own, because "select a file or folder
 // first" is nonsense next to an empty Trash.
 assert.equal(whyDisabled('trashEmpty', {...allowedCtx(), count: 0, one: false}).sentence, 'The Trash is already empty.');
 assert.equal(whyDisabled('trashRestore', {...allowedCtx(), count: 0, one: false}).sentence, 'Select items in Trash to restore.');
});

test('the wrong KIND of thing is refused in the kind’s own words', () => {
 assert.equal(whyDisabled('viewText', {...allowedCtx(), kind: 'special'}).sentence, KIND_SENTENCES.special);
 assert.equal(whyDisabled('viewText', {...allowedCtx(), kind: 'special'}).sentence, 'This is a device file, so it cannot be edited as text.');
 assert.equal(whyDisabled('viewText', {...allowedCtx(), kind: 'dir'}).sentence, KIND_SENTENCES.dir);
 assert.equal(whyDisabled('viewText', {...allowedCtx(), kind: 'broken'}).sentence, KIND_SENTENCES.broken);
 // The results view never followed the link, so it must not call it broken.
 assert.equal(whyDisabled('viewText', {...allowedCtx(), kind: 'unfollowed'}).sentence, KIND_SENTENCES.unfollowed);
 assert.match(KIND_SENTENCES.unfollowed, /was not inspected/);
});

test('entryKind maps the badge predicates onto the table’s one word', () => {
 assert.equal(entryKind({dir: true, readable: false, broken: false}), 'dir');
 assert.equal(entryKind({dir: false, readable: true, broken: false}), 'file');
 assert.equal(entryKind({dir: false, readable: false, broken: false}), 'special');
 assert.equal(entryKind({dir: true, readable: false, broken: true}), 'broken', 'broken wins: nothing about it is known');
});

test('the guard’s own reason is passed through unchanged, and falls back when there is none', () => {
 const own = whyDisabled('delete', {...allowedCtx(), guard: {denied: true, reason: 'The app’s own configuration cannot be changed here.'}});
 assert.equal(own.sentence, 'The app’s own configuration cannot be changed here.');
 assert.equal(whyDisabled('delete', {...allowedCtx(), guard: {denied: true}}).sentence, GUARD_SENTENCE);
});

test('the read-only sentence is the contract’s, verbatim', () => {
 assert.equal(READONLY_SENTENCE, 'Read-only mode is on, so nothing can be changed. An administrator can turn it off in Settings.');
 assert.equal(whyDisabled('newFolder', {...allowedCtx(), readOnly: true}).sentence, READONLY_SENTENCE);
});

test('an unknown action is a programming error, not a silently enabled button', () => {
 assert.throws(() => whyDisabled('selfDestruct', allowedCtx()), /unknown action selfDestruct/);
});

test('reasonsFor lists every applicable cause in precedence order', () => {
 const all = reasonsFor('permissions', {
  ...allowedCtx(), readOnly: true, count: 0, one: false, entry: foreign, guard: {denied: true, reason: 'protected'},
 });
 assert.deepEqual(all.map(r => r.cause), ['readonly', 'selection', 'capability', 'guard']);
 assert.deepEqual(CAUSES, ['readonly', 'selection', 'capability', 'guard']);
});
