// Run with: node --test internal/web/banners_test.mjs
//
// M4 contract §8.3/§8.4: the two persistent bars, keyed on the session's
// read-only state and on which DOOR it came in through. The break-glass bar is
// the one sentence standing between an operator and a support tree full of
// root-owned files nobody else can delete (§2.4, §18.5), so its wording is
// pinned character for character.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {
 BREAK_GLASS_DOOR, BREAK_GLASS_TEXT, DOORS, READONLY_ADMIN_TAIL, READONLY_TEXT,
 READONLY_USER_TAIL, bannerSignature, banners, identityLabel,
} from './static/js/banners.js';

const session = (extra = {}) => ({authenticated: true, user: 'sveinung', uid: 1000, admin: false, readOnly: false, canWrite: true, door: 'qts', ...extra});

test('a normal writable QTS session shows no bar at all', () => {
 assert.deepEqual(banners(session()), []);
 assert.deepEqual(banners(null), [], 'no session, nothing to describe');
});

test('read-only shows the bar, and says something different to an admin than to a user', () => {
 const user = banners(session({readOnly: true, canWrite: false}));
 assert.equal(user.length, 1);
 assert.equal(user[0].id, 'bannerReadonly');
 assert.equal(user[0].text, READONLY_TEXT);
 assert.equal(user[0].text, 'Read-only mode — no changes can be made.');
 assert.equal(user[0].tail, READONLY_USER_TAIL);
 assert.equal(user[0].action, null, 'a non-admin is never offered a control that would 403');
 const admin = banners(session({readOnly: true, canWrite: false, admin: true}));
 assert.equal(admin[0].tail, READONLY_ADMIN_TAIL);
 assert.deepEqual(admin[0].action, {id: 'bannerReadonlySettings', label: 'Open Settings'});
});

test('canWrite alone is enough: the bar follows the thing that actually refuses the write', () => {
 const bars = banners({user: 'x', canWrite: false});
 assert.equal(bars.length, 1);
 assert.equal(bars[0].id, 'bannerReadonly');
});

test('the break-glass bar appears for door "local" and for no other door', () => {
 for (const door of DOORS) {
  const bars = banners(session({door}));
  const shown = bars.some(bar => bar.id === 'bannerBreakGlass');
  assert.equal(shown, door === BREAK_GLASS_DOOR, door);
 }
 // A session with no door field at all (an older server, or a payload that
 // never carried one) must not conjure an emergency banner.
 assert.deepEqual(banners(session({door: undefined})), []);
 assert.deepEqual(DOORS, ['qts', 'credential', 'local'], 'the three doors of §6.1');
});

test('the break-glass wording is the contract’s, verbatim', () => {
 const [bar] = banners(session({door: 'local', admin: true}));
 assert.equal(bar.text, BREAK_GLASS_TEXT);
 assert.equal(bar.text,
  'Emergency access. You are signed in with the local administrator account, not a QTS user. ' +
  'Everything you create here will be owned by root.',
  'the contract’s sentence, verbatim — internal/web/ui_door_pin_test.go pins the same one from Go');
 assert.match(bar.text, /owned by root\.$/, 'the ownership consequence is the point of the bar');
 assert.equal(bar.kind, 'warn');
 assert.equal(bar.action, null, 'never dismissible, and nothing to press');
});

test('a read-only break-glass session shows BOTH bars, read-only first', () => {
 const bars = banners(session({door: 'local', admin: true, readOnly: true, canWrite: false}));
 assert.deepEqual(bars.map(bar => bar.id), ['bannerReadonly', 'bannerBreakGlass']);
});

test('the Session dialog names the emergency door, not a development identity (finding 4)', () => {
 // A break-glass session has no QTS `kind`, so viaQTS is false — which used to
 // make this dialog call an emergency administrator a "Pinned development
 // identity" on the one door where being told what you are matters most.
 assert.equal(identityLabel(session({door: 'local', viaQTS: false, admin: true})), 'Emergency access (local administrator)');
 assert.equal(identityLabel(session({door: 'qts', viaQTS: true})), 'QTS session');
 assert.equal(identityLabel(session({door: 'credential', viaQTS: true})), 'QTS session');
 assert.equal(identityLabel(session({door: 'qts', viaQTS: false})), 'Pinned development identity', 'the dev loop still says what it is');
 assert.equal(identityLabel(null), 'Pinned development identity');
});

test('the signature changes only when the bars do — a navigation is not an announcement', () => {
 const a = banners(session({readOnly: true, canWrite: false}));
 const b = banners(session({readOnly: true, canWrite: false}));
 assert.equal(bannerSignature(a), bannerSignature(b), 'same state, same signature, announced once');
 assert.notEqual(bannerSignature(a), bannerSignature(banners(session())));
 assert.equal(bannerSignature([]), '');
 assert.notEqual(
  bannerSignature(banners(session({readOnly: true, canWrite: false, admin: true}))),
  bannerSignature(a), 'the admin tail is a different sentence, and is announced');
});
