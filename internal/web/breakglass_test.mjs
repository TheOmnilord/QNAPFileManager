// Run with: node --test internal/web/breakglass_test.mjs
//
// The emergency door's sign-in (M4 contract §2, round-1 finding 1). The bug it
// closes: on https://<nas>:8771/ an unauthenticated visitor was told to "sign in
// on the QTS desktop" — the one instruction that cannot be followed there,
// because the QTS desktop being broken is why this listener exists.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';

// A document double: enough for the form, the error line and the QTS panel.
class Node {
 constructor(id = '') { this.id = id; this.attrs = {}; this.children = []; this.listeners = {}; this.textContent = ''; this.hidden = false; this.value = ''; this.disabled = false; this.focused = 0; this.selected = 0; }
 setAttribute(k, v) { this.attrs[k] = String(v); }
 getAttribute(k) { return this.attrs[k] ?? null; }
 append(...kids) { this.children.push(...kids); }
 replaceChildren(...kids) { this.children = kids; }
 addEventListener(type, fn) { this.listeners[type] = fn; }
 focus() { this.focused++; }
 select() { this.selected++; }
 close() { this.open = false; }
}
const nodes = new Map();
const $ = sel => { if (!nodes.has(sel)) nodes.set(sel, new Node(sel)); return nodes.get(sel); };
globalThis.document = {querySelector: $, querySelectorAll: () => [], createElement: () => new Node(), addEventListener() {}, activeElement: null};
globalThis.window = {addEventListener() {}};

const {
 LOGIN_ERRORS, LOGIN_ROUTE, LOCAL_LISTENER, hideLocalSignIn, initBreakGlass, listenerOf,
 loginBody, loginErrorText, onLocalListener, showLocalSignIn, signInView, submitLogin,
} = await import('./static/js/breakglass.js');

const html = readFileSync(new URL('./static/index.html', import.meta.url), 'utf8');

test('the local form is shown for listener "local" and unauthenticated, and never otherwise', () => {
 assert.equal(signInView({authenticated: false, listener: 'local', door: 'local'}), 'local');
 assert.equal(signInView({authenticated: false, listener: '', door: 'qts'}), 'qts');
 assert.equal(signInView({authenticated: false}), 'qts', 'an unknown listener is the QTS door');
 assert.equal(signInView({authenticated: true, listener: 'local', door: 'local'}), 'none');
 assert.equal(signInView({authenticated: true, listener: '', door: 'qts'}), 'none');
 assert.equal(signInView(null), 'qts');
});

test('listener is authoritative; door is the fallback for a payload that has no listener yet', () => {
 assert.equal(listenerOf({listener: 'local'}), LOCAL_LISTENER);
 assert.equal(listenerOf({listener: 'main', door: 'local'}), 'main', 'listener wins when both are present');
 assert.equal(listenerOf({door: 'local'}), LOCAL_LISTENER, 'door local is only ever issued by that listener');
 assert.equal(listenerOf({door: 'qts'}), '');
 assert.equal(listenerOf({}), '');
 assert.equal(onLocalListener({listener: 'local'}), true);
 assert.equal(onLocalListener({listener: 'main'}), false);
});

test('showing the local form hides the QTS notice, and clears the field and the error', () => {
 $('#signin').hidden = false;
 $('#bgPassword').value = 'typed';
 $('#bgError').textContent = 'old'; $('#bgError').hidden = false;
 showLocalSignIn();
 assert.equal($('#signin').hidden, true, 'the QTS notice must never show on the local listener');
 assert.equal($('#bgSignin').hidden, false);
 assert.equal($('#bgPassword').value, '');
 assert.equal($('#bgError').hidden, true);
 assert.ok($('#bgPassword').focused > 0, 'the field takes focus');
 hideLocalSignIn();
 assert.equal($('#bgSignin').hidden, true);
});

test('the request is a POST of exactly {password} to the break-glass route', async () => {
 const calls = [];
 const api = (route, params, options) => { calls.push({route, params, options}); return Promise.resolve(null); };
 let reloaded = 0;
 const ok = await submitLogin({api, onSignedIn: () => { reloaded++; }, password: 'correct horse battery'});
 assert.equal(ok, true);
 assert.equal(calls.length, 1);
 assert.equal(calls[0].route, LOGIN_ROUTE);
 assert.equal(calls[0].route, 'api/breakglass/login');
 assert.equal(calls[0].options.method, 'POST');
 assert.equal(calls[0].options.headers['Content-Type'], 'application/json');
 assert.deepEqual(JSON.parse(calls[0].options.body), {password: 'correct horse battery'});
 assert.deepEqual(Object.keys(JSON.parse(calls[0].options.body)), ['password'], 'nothing else travels');
 assert.equal(reloaded, 1, 'the session is re-read after a successful sign-in');
 assert.equal($('#bgSignin').hidden, true, 'the form goes away');
 assert.equal($('#bgPassword').value, '', 'the password is not left in the field');
});

test('loginBody never carries anything but a string password', () => {
 assert.deepEqual(loginBody('x'), {password: 'x'});
 assert.deepEqual(loginBody(undefined), {password: ''});
 assert.deepEqual(loginBody(null), {password: ''});
});

test('the three server refusals each render their own line', async () => {
 const cases = [
  ['auth_failed', 'Wrong password.'],
  ['locked_out', 'Too many attempts; try again later.'],
  ['rate_limited', 'Too many attempts; try again later.'],
 ];
 for (const [code, want] of cases) {
  const api = () => Promise.reject(Object.assign(new Error('That password was not accepted.'), {code, status: code === 'auth_failed' ? 401 : 429}));
  const ok = await submitLogin({api, onSignedIn: () => assert.fail('must not reload the session'), password: 'wrong'});
  assert.equal(ok, false, code);
  assert.equal($('#bgError').hidden, false, code);
  assert.equal($('#bgError').textContent, want, code);
  assert.equal(LOGIN_ERRORS[code], want);
 }
});

test('a Retry-After is repeated in words, so nobody hammers their own lockout longer', () => {
 assert.equal(loginErrorText({code: 'locked_out', retryAfter: '60'}), 'Too many attempts; try again later. Try again in 60 seconds.');
 assert.equal(loginErrorText({code: 'locked_out', retryAfter: '1'}), 'Too many attempts; try again later. Try again in 1 second.');
 assert.equal(loginErrorText({code: 'locked_out'}), 'Too many attempts; try again later.');
 assert.equal(loginErrorText({code: 'locked_out', retryAfter: 'soon'}), 'Too many attempts; try again later.');
 assert.equal(loginErrorText({code: 'auth_failed'}), 'Wrong password.');
 // Anything the table does not name still says something, and never nothing.
 assert.equal(loginErrorText({message: 'The service is restarting.'}), 'The service is restarting.');
 assert.equal(loginErrorText({}), 'The password could not be checked.');
});

test('an empty password is refused here, without a request', async () => {
 let called = 0;
 const ok = await submitLogin({api: () => { called++; }, onSignedIn: () => {}, password: ''});
 assert.equal(ok, false);
 assert.equal(called, 0, 'the door is not knocked on for nothing');
 assert.equal($('#bgError').textContent, 'Enter the local administrator password.');
});

test('the submit button is released whether the attempt succeeded or failed', async () => {
 await submitLogin({api: () => Promise.reject(Object.assign(new Error('no'), {code: 'auth_failed'})), onSignedIn: () => {}, password: 'x'});
 assert.equal($('#bgSubmit').disabled, false);
 await submitLogin({api: () => Promise.resolve(null), onSignedIn: () => {}, password: 'x'});
 assert.equal($('#bgSubmit').disabled, false);
});

test('the form submits on Enter as well as on the button, and never navigates', () => {
 let submitted = 0;
 initBreakGlass({api: () => { submitted++; return Promise.resolve(null); }, onSignedIn: () => {}});
 let defaulted = false;
 $('#bgPassword').value = 'secret';
 $('#bgForm').listeners.submit({preventDefault() { defaulted = true; }});
 assert.equal(defaulted, true, 'a form that navigates loses the page it was signing into');
 assert.equal(submitted, 1);
});

// --- the notice that must never appear here ----------------------------------

const {signInNotice, connectionNotice} = await import('./static/js/api.js');
const {state, update} = await import('./static/js/state.js');

test('a sign-out on the emergency listener shows the password form, not the QTS notice', () => {
 update({listener: 'local', session: null});
 $('#signin').hidden = false;
 signInNotice();
 assert.equal($('#signin').hidden, true, '"sign in on the QTS desktop" is unfollowable at this door');
 assert.equal($('#bgSignin').hidden, false);
});

test('a sign-out anywhere else still shows the QTS notice, and no password form', () => {
 update({listener: '', session: null});
 $('#bgSignin').hidden = false;
 signInNotice();
 assert.equal($('#signin').hidden, false);
 assert.equal($('#bgSignin').hidden, true, 'the local door is not offered where it does not exist');
 assert.match($('#signin p').textContent, /QTS desktop/);
});

test('a connection failure at the emergency door lands under the password field', () => {
 update({listener: 'local', session: null});
 $('#signin').hidden = true;
 connectionNotice('Unable to connect', 'The service is not answering.');
 assert.equal($('#bgSignin').hidden, false);
 assert.equal($('#bgError').textContent, 'The service is not answering.');
 assert.equal($('#signin').hidden, true, 'never a panel naming the QTS desktop as the remedy');
 update({listener: ''});
});

test('the shell carries the form, labelled, with a password field and an error line', () => {
 const section = html.match(/<section id="bgSignin"[\s\S]*?<\/section>/);
 assert.ok(section, '#bgSignin must exist in the shell');
 assert.match(section[0], /aria-labelledby="bgTitle"/);
 assert.match(section[0], /hidden/, 'it is hidden until the server says which door this is');
 assert.match(section[0], /<label for="bgPassword">Local administrator password<\/label>/);
 assert.match(section[0], /id="bgPassword" type="password"/);
 assert.match(section[0], /id="bgSubmit" type="submit">Sign in</);
 assert.match(section[0], /id="bgError"[^>]*role="alert"/);
 // The consequence is stated before the password is typed, not after.
 assert.match(section[0], /owned by root/);
});
