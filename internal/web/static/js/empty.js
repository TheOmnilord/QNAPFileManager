// empty.js decides what a pane with nothing in it says (M4 contract §8).
//
// The load-bearing case is the second one: today a non-admin walking into
// /etc/ssh sees an empty list and concludes the app is broken. An empty folder
// and a folder you cannot read must never look the same — so "we found nothing"
// and "we were not allowed to look" are different states with different
// sentences, and the kernel's own verdict is reported rather than summarised
// (INV-2).
//
// Numbers, never "some": every state that can name a count or a bound names it.
// That is what distinguishes "nothing is there" from "we stopped looking".
//
// Pure — no DOM, no imports — so the selection between the states is a unit
// test rather than a screenshot.

// The named states. `listing-failed` is the sixth: a listing that failed for a
// reason that is NOT permission (the worker died, the path vanished) is not an
// empty folder either, and saying "this folder is empty" over a failure would
// be the same lie in a different hat.
export const EMPTY_STATES = [
 'folder-empty', 'listing-refused', 'listing-failed', 'filter-no-match', 'search-no-hits', 'trash-empty', 'jobs-idle',
];

const REFUSED_CODES = new Set(['permission', 'protected', 'readonly', 'read_only', 'unauthorized']);

const count = value => Math.max(0, Math.floor(Number(value) || 0)).toLocaleString();

// listingRefused builds the §8.1 sentence. Owner and mode are named when the
// caller could find them out (a stat of the folder itself usually survives a
// refused listing, because reading a directory and traversing to it are
// different permissions); when it could not, the server's own message is the
// verdict and it is quoted rather than paraphrased.
export function listingRefused({owner = '', mode = '', message = ''} = {}) {
 const head = 'You do not have permission to list this folder.';
 if (owner && mode) return `${head} It is owned by ${owner} and its mode is ${mode}.`;
 if (owner) return `${head} It is owned by ${owner}.`;
 if (mode) return `${head} Its mode is ${mode}.`;
 return message ? `${head} The system said: ${message}` : head;
}

// volumeOf names the volume a path lives on, for the Trash sentence (§8.1 asks
// it to name "the volume it is talking about").
//
// It is a spelling rule, not a mount lookup: /share/<x> and /mnt/<x> are the
// two places a QTS volume is reachable, and /share/external/<device> is the
// third. Anything else — /etc, /, a raw device path — has no volume this side
// can name honestly, and the sentence then says "this volume" rather than
// inventing one.
export function volumeOf(path) {
 const parts = String(path ?? '').split('/').filter(Boolean);
 if (parts.length < 2) return '';
 if (parts[0] === 'share' && parts[1] === 'external') return parts.length >= 3 ? `/share/external/${parts[2]}` : '';
 if (parts[0] === 'share' || parts[0] === 'mnt') return `/${parts[0]}/${parts[1]}`;
 return '';
}

// emptyState answers for one pane. kind is 'list' | 'results' | 'trash' |
// 'jobs'; it returns null when the pane has something to show.
//
// Returned shape: {state, sentence, detail, action} — `action` is at most one
// offer ({id,label}), per §8.1's "one sentence plus at most one action".
export function emptyState(kind, ctx = {}) {
 switch (kind) {
 case 'list': return listState(ctx);
 case 'results': return resultsState(ctx);
 case 'trash': return trashState(ctx);
 case 'jobs': return jobsState(ctx);
 default: return null;
 }
}

function listState({loading = false, total = 0, loaded = 0, filter = '', matches = 0, error = null, owner = '', mode = '', canCreate = false} = {}) {
 if (loading) return null;
 if (error) {
  const code = String(error.code || '');
  if (REFUSED_CODES.has(code)) {
   return {state: 'listing-refused', sentence: listingRefused({owner, mode, message: error.message || ''}), detail: '', action: null};
  }
  return {
   state: 'listing-failed',
   sentence: `This folder could not be listed. ${error.message || 'The request did not complete.'}`,
   detail: '', action: null,
  };
 }
 if (total === 0) {
  return {
   state: 'folder-empty',
   sentence: 'This folder is empty.',
   detail: '',
   action: canCreate ? {id: 'btnMkdir', label: 'New folder'} : null,
  };
 }
 if (filter && matches === 0) {
  return {
   state: 'filter-no-match',
   sentence: `No loaded name matches “${filter}”. ${count(loaded)} ${loaded === 1 ? 'entry is' : 'entries are'} loaded; press Ctrl+F to search the whole subtree.`,
   detail: total > loaded ? `${count(total)} entries are in this folder; the rest load as you scroll.` : '',
   action: {id: 'btnSearch', label: 'Search this folder and below'},
  };
 }
 return null;
}

function resultsState({hits = 0, root = '', visited = null, detail = ''} = {}) {
 if (hits > 0) return null;
 const where = root ? ` under ${root}` : '';
 const seen = Number.isFinite(Number(visited)) && Number(visited) > 0
  ? ` ${count(visited)} ${Number(visited) === 1 ? 'entry was' : 'entries were'} visited.`
  : '';
 return {
  state: 'search-no-hits',
  sentence: `No match${where}.${seen}`,
  // The bound that stopped it, when one did: a search that hit its hit cap,
  // its visit cap or its minute is not the same answer as one that finished.
  detail: detail ? `The search stopped early: ${detail}` : '',
  action: null,
 };
}

function trashState({items = 0, dirName = '', volume = ''} = {}) {
 if (items > 0) return null;
 const where = volume ? ` on ${volume}` : ' on this volume';
 return {
  state: 'trash-empty',
  sentence: `Trash is empty${where}.`,
  detail: dirName ? `Trash lives in ${dirName} on each volume.` : '',
  action: null,
 };
}

function jobsState({visible = 0, finished = 0} = {}) {
 if (visible > 0) return null;
 return {
  state: 'jobs-idle',
  sentence: 'Nothing is running.',
  detail: finished > 0
   ? `${count(finished)} finished operation${Number(finished) === 1 ? '' : 's'} ${Number(finished) === 1 ? 'was' : 'were'} cleared from this list.`
   : 'Copies, moves, deletes and searches appear here while they run.',
  action: null,
 };
}
