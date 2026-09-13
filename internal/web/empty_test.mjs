// Run with: node --test internal/web/empty_test.mjs
//
// M4 contract §8: the five named empty states, and above all the difference
// between "this folder is empty" and "you were not allowed to look". A
// non-admin walking into /etc/ssh must not see the same thing as somebody
// standing in a folder with nothing in it.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {EMPTY_STATES, emptyState, listingRefused, volumeOf} from './static/js/empty.js';

test('an empty folder and a refused listing are different states with different sentences', () => {
 const empty = emptyState('list', {total: 0});
 const refused = emptyState('list', {total: 0, error: {code: 'permission', message: 'Permission denied.'}});
 assert.equal(empty.state, 'folder-empty');
 assert.equal(empty.sentence, 'This folder is empty.');
 assert.equal(refused.state, 'listing-refused');
 assert.notEqual(refused.sentence, empty.sentence);
 assert.match(refused.sentence, /^You do not have permission to list this folder\./);
});

test('the refused sentence names the kernel’s verdict when the stat could find it', () => {
 const refused = emptyState('list', {total: 0, error: {code: 'permission', message: 'Permission denied.'}, owner: 'root', mode: '0750'});
 assert.equal(refused.sentence, 'You do not have permission to list this folder. It is owned by root and its mode is 0750.');
});

test('with no owner or mode the refusal quotes the server rather than inventing facts', () => {
 assert.equal(
  listingRefused({message: 'Permission denied.'}),
  'You do not have permission to list this folder. The system said: Permission denied.');
 assert.equal(listingRefused({}), 'You do not have permission to list this folder.');
 assert.equal(listingRefused({owner: 'root'}), 'You do not have permission to list this folder. It is owned by root.');
 assert.equal(listingRefused({mode: '0700'}), 'You do not have permission to list this folder. Its mode is 0700.');
});

test('a protected path is a refusal; a failure that is not about permission says so as a failure', () => {
 for (const code of ['permission', 'protected', 'readonly', 'read_only', 'unauthorized']) {
  assert.equal(emptyState('list', {total: 0, error: {code, message: 'no'}}).state, 'listing-refused', code);
 }
 const failed = emptyState('list', {total: 0, error: {code: 'worker_gone', message: 'The worker stopped.'}});
 assert.equal(failed.state, 'listing-failed');
 assert.equal(failed.sentence, 'This folder could not be listed. The worker stopped.');
});

test('an empty folder offers New folder only where it could actually be used', () => {
 assert.deepEqual(emptyState('list', {total: 0, canCreate: true}).action, {id: 'btnMkdir', label: 'New folder'});
 assert.equal(emptyState('list', {total: 0, canCreate: false}).action, null, 'read-only: no offer that would 403');
});

test('a loading list has no empty state at all — "empty" is not a thing you say while looking', () => {
 assert.equal(emptyState('list', {loading: true, total: 0}), null);
});

test('a filter that matched nothing counts what is loaded and points at the real search', () => {
 const info = emptyState('list', {total: 4182, loaded: 4182, filter: 'x', matches: 0});
 assert.equal(info.state, 'filter-no-match');
 // The separator is the READER's, not this machine's: the app formats every
 // count with toLocaleString, so the expectation is built the same way.
 assert.equal(info.sentence, `No loaded name matches “x”. ${(4182).toLocaleString()} entries are loaded; press Ctrl+F to search the whole subtree.`);
 assert.deepEqual(info.action, {id: 'btnSearch', label: 'Search this folder and below'});
 // A partly loaded directory says that too, rather than implying 4,182 is all.
 const partial = emptyState('list', {total: 312004, loaded: 2000, filter: 'zz', matches: 0});
 assert.ok(partial.sentence.includes(`${(2000).toLocaleString()} entries are loaded`), partial.sentence);
 assert.equal(partial.detail, `${(312004).toLocaleString()} entries are in this folder; the rest load as you scroll.`);
});

test('a filter that matched something is not an empty state', () => {
 assert.equal(emptyState('list', {total: 10, loaded: 10, filter: 'a', matches: 3}), null);
 assert.equal(emptyState('list', {total: 10, loaded: 10, filter: '', matches: 0}), null);
});

test('a search with no hits names the root, the count visited and the bound that stopped it', () => {
 const info = emptyState('results', {hits: 0, root: '/share/Public', visited: 312004});
 assert.equal(info.state, 'search-no-hits');
 assert.equal(info.sentence, `No match under /share/Public. ${(312004).toLocaleString()} entries were visited.`);
 const capped = emptyState('results', {hits: 0, root: '/share', visited: 500000, detail: 'stopped after 500000 entries'});
 assert.equal(capped.detail, 'The search stopped early: stopped after 500000 entries');
 // Nothing is invented when the walk did not report a count.
 assert.equal(emptyState('results', {hits: 0, root: '/share'}).sentence, 'No match under /share.');
 assert.equal(emptyState('results', {hits: 4, root: '/share'}), null);
});

test('an empty Trash NAMES the volume it is talking about (finding 5)', () => {
 const named = emptyState('trash', {items: 0, dirName: '.@qfm_trash', volume: '/share/CACHEDEV1_DATA'});
 assert.equal(named.state, 'trash-empty');
 assert.equal(named.sentence, 'Trash is empty on /share/CACHEDEV1_DATA.');
 assert.equal(named.detail, 'Trash lives in .@qfm_trash on each volume.', 'and the detail says the panel covered them all');
 // Only where there is no volume to name honestly does it stay generic.
 const generic = emptyState('trash', {items: 0, dirName: '.@qfm_trash'});
 assert.equal(generic.sentence, 'Trash is empty on this volume.');
 assert.equal(emptyState('trash', {items: 3}), null);
});

test('volumeOf names a volume only where one can be named honestly', () => {
 assert.equal(volumeOf('/share/CACHEDEV1_DATA/Public/report.txt'), '/share/CACHEDEV1_DATA');
 assert.equal(volumeOf('/share/CACHEDEV1_DATA'), '/share/CACHEDEV1_DATA');
 assert.equal(volumeOf('/share/Public'), '/share/Public');
 assert.equal(volumeOf('/mnt/HDA_ROOT/etc'), '/mnt/HDA_ROOT');
 assert.equal(volumeOf('/share/external/DEV3301_1/photos'), '/share/external/DEV3301_1');
 // Nothing outside the two volume parents is guessed at.
 assert.equal(volumeOf('/etc/ssh'), '');
 assert.equal(volumeOf('/share'), '');
 assert.equal(volumeOf('/share/external'), '');
 assert.equal(volumeOf('/'), '');
 assert.equal(volumeOf(''), '');
 assert.equal(volumeOf(null), '');
});

test('an idle jobs panel says what it is for, and counts what it cleared', () => {
 const idle = emptyState('jobs', {visible: 0, finished: 0});
 assert.equal(idle.state, 'jobs-idle');
 assert.equal(idle.sentence, 'Nothing is running.');
 assert.match(idle.detail, /appear here while they run/);
 assert.equal(emptyState('jobs', {visible: 0, finished: 1}).detail, '1 finished operation was cleared from this list.');
 assert.equal(emptyState('jobs', {visible: 0, finished: 7}).detail, '7 finished operations were cleared from this list.');
 assert.equal(emptyState('jobs', {visible: 2, finished: 0}), null);
});

test('every state a pane can produce is a NAMED one', () => {
 const produced = [
  emptyState('list', {total: 0}),
  emptyState('list', {total: 0, error: {code: 'permission'}}),
  emptyState('list', {total: 0, error: {code: 'internal', message: 'x'}}),
  emptyState('list', {total: 5, loaded: 5, filter: 'q', matches: 0}),
  emptyState('results', {hits: 0, root: '/'}),
  emptyState('trash', {items: 0}),
  emptyState('jobs', {visible: 0}),
 ];
 for (const info of produced) {
  assert.ok(EMPTY_STATES.includes(info.state), info.state);
  assert.ok(info.sentence.trim().length > 0, info.state);
 }
 assert.equal(produced.length, EMPTY_STATES.length, 'one example per named state');
 assert.equal(emptyState('nowhere', {}), null);
});
