// breakglass.js is the emergency door's own sign-in (M4 contract §2, §8.4).
//
// It exists because of the one thing the QTS door cannot do here: on
// https://<nas>:8771/ an unauthenticated visitor used to be told to "sign in on
// the QTS desktop", which is the instruction that cannot be followed — the QTS
// desktop being broken is the reason this listener exists at all.
//
// Which door a page is standing at is the SERVER's answer, never a guess from
// the URL: an unauthenticated GET /api/session on the break-glass listener
// answers exactly {authenticated:false, listener:"local"} — two fields and no
// more, so a LAN scanner learns nothing else — and that single field decides
// which sign-in is rendered.
//
// The module takes `api` as an argument rather than importing it, because
// api.js has to ask THIS module which notice to show on a 401 — injecting the
// one function keeps that from being an import cycle.
import {$, announce} from './dom.js';

export const LOCAL_LISTENER = 'local';
export const LOGIN_ROUTE = 'api/breakglass/login';

// The error line, per code. The wording never says which of the four failure
// paths it was — the server deliberately answers identically for a wrong
// password, an unconfigured one and a malformed body (§5.2), and a UI that
// guessed between them would be inventing information the server withheld.
export const LOGIN_ERRORS = {
 auth_failed: 'Wrong password.',
 locked_out: 'Too many attempts; try again later.',
 rate_limited: 'Too many attempts; try again later.',
 permission: 'The browser could not verify this request. Reload the page and try again.',
 session_store_full: 'Too many emergency sessions are open. Try again shortly.',
};

// listenerOf is which listener answered. `listener` is authoritative; `door` is
// the fallback for a payload that predates it, and it is safe as one because
// door "local" is only ever issued by the break-glass listener (§2.1).
export function listenerOf(session) {
 const listener = String(session?.listener ?? '');
 if (listener) return listener;
 return String(session?.door ?? '') === LOCAL_LISTENER ? LOCAL_LISTENER : '';
}

export const onLocalListener = session => listenerOf(session) === LOCAL_LISTENER;

// signInView is which sign-in a payload asks for: 'none' when there is a
// session, 'local' on the emergency listener, 'qts' everywhere else.
export function signInView(session) {
 if (session?.authenticated) return 'none';
 return onLocalListener(session) ? 'local' : 'qts';
}

// loginBody is what POST /api/breakglass/login carries, and nothing else.
export function loginBody(password) { return {password: String(password ?? '')}; }

// loginErrorText turns a failed login into the one line under the field. A
// Retry-After is repeated in words, because "try again later" without a number
// is the sentence that makes an operator hammer the door and extend their own
// lockout.
export function loginErrorText(err) {
 const base = LOGIN_ERRORS[String(err?.code ?? '')] || err?.message || 'The password could not be checked.';
 const seconds = Math.round(Number(err?.retryAfter));
 if (!Number.isFinite(seconds) || seconds <= 0) return base;
 return `${base} Try again in ${seconds.toLocaleString()} second${seconds === 1 ? '' : 's'}.`;
}

// --- the DOM half ------------------------------------------------------------

function setError(message) {
 const box = $('#bgError');
 if (!box) return;
 box.textContent = message || '';
 box.hidden = !message;
 if (message) announce(message);
}

// showLocalSignIn puts the emergency form on screen. The QTS notice is hidden
// by the same call, because the two are alternatives and showing the wrong one
// here is the whole finding.
export function showLocalSignIn() {
 const form = $('#bgSignin');
 if (!form) return;
 $('#signin').hidden = true;
 form.hidden = false;
 setError('');
 const field = $('#bgPassword');
 if (field) { field.value = ''; field.focus?.(); }
}

export function hideLocalSignIn() { const form = $('#bgSignin'); if (form) form.hidden = true; }

// localNotice is how a connection failure reaches a visitor at this door: under
// the password field, where they are already looking, instead of in a QTS panel
// that has nothing to do with this listener.
export function localNotice(message) { setError(message); }

// submitLogin posts the password and, on success, hands back to the caller's
// session reload. It is exported for the test: the request body and the three
// error renderings are what this module has to get right, and both are visible
// here without a browser.
export async function submitLogin({api, onSignedIn, password}) {
 if (!password) { setError('Enter the local administrator password.'); return false; }
 const button = $('#bgSubmit');
 if (button) button.disabled = true;
 try {
  // No CSRF header: no session exists yet to bind a token to, and the route is
  // exempt for exactly that reason (§10). The Origin check and SameSite still
  // apply, and the token arrives with the session on the next /api/session.
  await api(LOGIN_ROUTE, {}, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(loginBody(password))});
  const field = $('#bgPassword');
  if (field) field.value = '';
  hideLocalSignIn();
  setError('');
  await onSignedIn();
  return true;
 } catch(err) {
  // A 401 makes api.js publish a sign-out, which re-shows this form and clears
  // the line; the message is set afterwards, so it is the last word.
  setError(loginErrorText(err));
  $('#bgPassword')?.select?.();
  return false;
 } finally {
  if (button) button.disabled = false;
 }
}

export function initBreakGlass({api, onSignedIn}) {
 $('#bgForm')?.addEventListener('submit', event => {
  event.preventDefault();
  submitLogin({api, onSignedIn, password: $('#bgPassword')?.value || ''});
 });
}
