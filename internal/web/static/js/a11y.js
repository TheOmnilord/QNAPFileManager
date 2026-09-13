// a11y.js is the focus contract (M4 contract §9.1/§9.2).
//
// The focus TRAP is the platform's: every dialog in this app is a native
// <dialog> opened with showModal(), and a conforming browser confines Tab to
// it. trapStep is the belt to that pair of braces — the QTS desktop frames the
// app inside its own document, and an embedded browser that mis-handles the
// modal cycle would otherwise let Tab walk out of a confirmation and into the
// list behind it, where Enter means "open" — and it is also what makes the rule
// testable in node, which showModal() is not.
//
// Everything above initA11y is pure.

// FOCUS_ORDER is §9.1's declared order, as element ids. A test reads
// index.html and asserts they appear in this order in the source, because focus
// order in a document with no positive tabindex IS source order — and the same
// test asserts there is no positive tabindex to break that equivalence.
export const FOCUS_ORDER = ['skipLink', 'toolbar', 'pathEdit', 'tree', 'list', 'status'];

// FOCUSABLE is the selector for what can hold focus inside a dialog. It is
// deliberately narrow: nothing inside a virtualised row is ever tabbable (§9.1),
// and no dialog contains one.
export const FOCUSABLE = [
 'a[href]', 'button:not([disabled])', 'input:not([disabled])', 'select:not([disabled])',
 'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])',
].join(',');

// trapStep says where Tab should go, given the focusable elements of a dialog
// in document order and the one that has focus now.
//
// It returns null when the browser's own behaviour is already right — an
// interior Tab, a key that is not Tab, a dialog with nothing focusable — and
// {index, wrapped} when the cycle has to be closed by hand. Pure over arrays,
// so every edge (focus outside the dialog, one focusable, none) is a unit test.
export function trapStep(elements, active, {key = '', shiftKey = false} = {}) {
 if (key !== 'Tab') return null;
 const list = (elements || []).filter(Boolean);
 if (!list.length) return null;
 const at = list.indexOf(active);
 // Focus is not in the dialog at all: pull it back to the appropriate end.
 if (at < 0) return {index: shiftKey ? list.length - 1 : 0, wrapped: true};
 if (!shiftKey && at === list.length - 1) return {index: 0, wrapped: true};
 if (shiftKey && at === 0) return {index: list.length - 1, wrapped: true};
 return null;
}

// initA11y wires the two halves the platform does not give us for free: the
// wrap above, and returning focus to the control that opened the dialog.
// dom.js records the opener; this is what spends it, on the `close` event —
// the one place every way of closing arrives (Escape, the Close button, and
// signInNotice() closing every dialog on a session change).
export function initA11y(deps) {
 const {dialogs, restoreFocus} = deps;
 for (const dialog of dialogs || []) {
  dialog.addEventListener('keydown', event => {
   if (event.key !== 'Tab') return;
   const elements = [...dialog.querySelectorAll(FOCUSABLE)].filter(node => !node.hidden && !node.closest('[hidden]'));
   const step = trapStep(elements, document.activeElement, event);
   if (!step) return;
   event.preventDefault();
   elements[step.index]?.focus?.();
  });
  dialog.addEventListener('close', () => restoreFocus(dialog));
 }
}
