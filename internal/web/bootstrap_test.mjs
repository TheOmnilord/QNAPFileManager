// Run with: node --test internal/web/bootstrap_test.mjs
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {sessionQuery,cleanSessionURL} from './static/js/bootstrap.js';

test('bootstrap forwards only the first SID and optional user, preserving encoding', () => {
 assert.deepEqual(sessionQuery('?sid=a%2Bb%26c%3D&user=alice%20smith&path=%2Fetc'),{sid:'a+b&c=',user:'alice smith'});
 assert.deepEqual(sessionQuery('?sid=first&sid=second&user='),{sid:'first',user:''});
 assert.deepEqual(sessionQuery('?sid='),{sid:''});
 assert.deepEqual(sessionQuery('?user=alice'),{});
 assert.deepEqual(sessionQuery(''),{});
});

test('cleanup removes every credential query field and preserves route and other parameters', () => {
 const href='https://nas/qnapfilemanager/?sid=secret&view=a%2Bb&user=alice&sid=again&user=bob#/etc';
 const clean=cleanSessionURL(href);
 assert.equal(clean,'/qnapfilemanager/?view=a%2Bb#/etc');
 assert.deepEqual(sessionQuery(new URL(clean,'https://nas').search),{});
 assert.equal(cleanSessionURL('https://nas/qnapfilemanager/?sid=secret&user=alice#/share'),'/qnapfilemanager/#/share');
 assert.equal(cleanSessionURL('https://nas/qnapfilemanager/#/share'),'/qnapfilemanager/#/share');
});
