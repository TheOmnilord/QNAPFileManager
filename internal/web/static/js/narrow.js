// narrow.js is the ≤ 768 px contract (M4 contract §9.5).
//
// The rule it exists to enforce: a secondary toolbar action COLLAPSES into the
// ⋯ menu, it does not disappear. Before M4, #btnMkdir and #btnUpload were
// `display:none` below 46rem, which removes function from a QTS desktop window
// that is simply narrow — the user could not create a folder at all and nothing
// told them why. Now the button is moved, never removed, and the menu item
// carries the same enablement and the same whyDisabled sentence as the button
// it stands for.
//
// overflowFor is pure over a width, so the five acceptance sizes are a table
// test rather than five screenshots.
import {$, el} from './dom.js';

// The rungs, in CSS pixels. 48rem = 768 px is the contract's explicit rung and
// 30rem = 480 px is the existing single-column one.
export const OVERFLOW_BREAKPOINT = 768;
export const COMPACT_BREAKPOINT = 480;

// SECONDARY collapses at the 768 px rung: everything that acts on a selection
// or creates something, which is exactly what a narrow toolbar cannot hold
// beside the navigation it also must keep.
export const SECONDARY = ['btnMkdir', 'btnUpload', 'btnView', 'btnProps', 'btnPerms', 'btnRename', 'btnCopy', 'btnMove', 'btnDelete'];
// COMPACT_EXTRA collapses as well on a phone-width screen.
export const COMPACT_EXTRA = ['btnTrash', 'btnShortcuts'];
// PRIMARY never collapses: navigation, download, search, the results switch,
// the jobs drawer and the ⋯ button itself. Stated as data so the test can
// assert the two sets do not overlap — a button in both would be a button that
// is hidden and has no menu item.
export const PRIMARY = ['btnTree', 'btnBack', 'btnFwd', 'btnUp', 'btnRefresh', 'btnDownload', 'btnDownloadAs', 'btnSearch', 'btnResults', 'btnJobs', 'btnMore'];

// The five sizes §9.5 fixes as acceptance.
export const ACCEPTANCE_WIDTHS = [1280, 1024, 900, 768, 375];

// overflowFor is the membership rule: which toolbar ids live in the ⋯ menu at
// this width. Above the rung the menu is empty and the button is hidden.
export function overflowFor(width) {
 const w = Number(width) || 0;
 // A width nobody could measure collapses nothing: the safe default is the full
 // toolbar, never a bar whose actions have all moved into a menu that a
 // layout-less document may not even be able to open.
 if (w <= 0) return [];
 if (w > OVERFLOW_BREAKPOINT) return [];
 if (w > COMPACT_BREAKPOINT) return [...SECONDARY];
 return [...SECONDARY, ...COMPACT_EXTRA];
}

// labelFor is what the menu item says. The toolbar button's own text is right
// for most of them; the two icon-only ones have no useful text at all.
export const MENU_LABELS = {btnShortcuts: 'Keyboard shortcuts', btnRefresh: 'Refresh'};
export function labelFor(id, text) {
 return MENU_LABELS[id] || String(text || '').trim() || id;
}

// mirrorOf is everything a menu item copies from the button it stands for.
//
// All FOUR spellings, not three: a menu item that took the title and the
// disabled state but left `aria-describedby` behind would say nothing at all to
// the screen-reader user it was added for — which is the whole reason §7.1 asks
// for the hidden node beside the title (round 1, finding 3). Two elements may
// point at one description; that is what makes the button and its stand-in say
// the same sentence rather than two copies that can drift.
//
// Pure, over the four values, so the mirroring is a unit test and not a
// screenshot of a menu.
export function mirrorOf({disabled = false, title = '', describedBy = ''} = {}) {
 return {
  disabled: !!disabled,
  ariaDisabled: String(!!disabled),
  title: String(title || ''),
  describedBy: String(describedBy || ''),
 };
}

// --- the DOM half ------------------------------------------------------------

// closeMore is exported so Escape anywhere can shut the menu.
export function closeMore() {
 const menu = $('#moreMenu');
 if (!menu || menu.hidden) return false;
 menu.hidden = true;
 $('#btnMore')?.setAttribute('aria-expanded', 'false');
 return true;
}

// syncOverflow moves the collapsed actions into the ⋯ menu and mirrors their
// state onto the menu items.
//
// It mirrors rather than re-derives: the item's `disabled`, its `title` and its
// aria-disabled come from the button refreshToolbar has already decided with
// whyDisabled, so there is exactly one place in the app that knows why an
// action is unavailable, and the narrow layout cannot drift from the wide one.
//
// It is called after every toolbar refresh and on resize, and it does nothing
// at all where there is no viewport to measure (node tests, and any document
// without layout).
export function syncOverflow() {
 const width = typeof window !== 'undefined' ? Number(window.innerWidth) || 0 : 0;
 if (!width) return [];
 const ids = overflowFor(width);
 const collapsed = new Set(ids);
 const menu = $('#moreMenu'), button = $('#btnMore');
 for (const id of [...SECONDARY, ...COMPACT_EXTRA]) {
  const source = $(`#${id}`);
  source?.classList?.toggle('inOverflow', collapsed.has(id));
 }
 if (!menu || !button) return ids;
 button.hidden = ids.length === 0;
 if (!ids.length) { closeMore(); menu.replaceChildren(); return ids; }
 menu.replaceChildren(...ids.map(id => {
  const source = $(`#${id}`);
  const item = el('button', {role: 'menuitem', tabindex: '-1', 'data-for': id}, labelFor(id, source?.textContent));
  const mirror = mirrorOf({disabled: source?.disabled, title: source?.title, describedBy: source?.getAttribute?.('aria-describedby')});
  item.disabled = mirror.disabled;
  item.setAttribute('aria-disabled', mirror.ariaDisabled);
  if (mirror.title) item.title = mirror.title;
  // The same hidden node the button points at: one sentence, two controls.
  if (mirror.describedBy) item.setAttribute('aria-describedby', mirror.describedBy);
  // Focus moves to the ⋯ button BEFORE the real button is pressed (Astra r1
  // #18). closeMore() hides the menu item that was focused, and the toolbar
  // button behind it is `display:none` at this width, so whatever a dialog then
  // opened captured as its opener (dom.js openDialog reads document.activeElement)
  // was invisible — More → New folder returned focus to nowhere on closing.
  // The ⋯ button is the visible control the user actually pressed, so it is the
  // one focus comes back to.
  item.addEventListener('click', () => { closeMore(); button.focus?.(); source?.click?.(); });
  return item;
 }));
 return ids;
}

// initNarrow wires the ⋯ menu and makes the folder drawer dismissible by a tap
// outside as well as by Escape (§9.5).
export function initNarrow() {
 const menu = $('#moreMenu'), button = $('#btnMore');
 button?.addEventListener('click', () => {
  const open = menu.hidden;
  menu.hidden = !open;
  button.setAttribute('aria-expanded', String(open));
  if (open) menu.querySelector('button:not([disabled])')?.focus?.();
 });
 menu?.addEventListener('keydown', event => {
  const items = [...menu.querySelectorAll('button:not([disabled])')], at = items.indexOf(document.activeElement);
  if (event.key === 'Escape') { closeMore(); button?.focus?.(); }
  else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
   event.preventDefault();
   items[(at + (event.key === 'ArrowDown' ? 1 : items.length - 1) + items.length) % items.length]?.focus?.();
  }
 });
 document.addEventListener('pointerdown', event => {
  if (!menu?.contains(event.target) && event.target !== button) closeMore();
  const tree = $('#tree');
  if (tree?.classList?.contains('open') && !tree.contains(event.target) && event.target !== $('#btnTree')) {
   tree.classList.remove('open');
   $('#btnTree')?.setAttribute('aria-expanded', 'false');
  }
 });
 window.addEventListener('resize', syncOverflow);
 syncOverflow();
}
