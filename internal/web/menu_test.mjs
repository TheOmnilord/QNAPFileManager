// Run with: node --test internal/web/menu_test.mjs
//
// Stabilization contract §3.7: the context menu opens where it was asked for —
// at the pointer for a right-click, just below the focused row for Shift+F10 —
// clamped inside the viewport and flipped up or left when it would overflow.
// menuPlacement is that rule as arithmetic, so every window size is a row here
// rather than a screenshot. The DOM half (the CSSOM rule list.js moves) is
// driven in list_test.mjs.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {menuPlacement} from './static/js/dom.js';

const viewport = {width:1024,height:768};
const menu = {width:180,height:240};
const pointer = (x,y) => ({left:x,top:y});
// A row's anchor is its left edge, from its top to its bottom.
const row = (left,top,bottom) => ({left,right:left,top,bottom});
const at = (anchor,size = menu,view = viewport) => menuPlacement({viewport:view,anchor,menu:size});

test('a right-click with room to spare opens the menu at the pointer', () => {
 assert.deepEqual(at(pointer(300,200)),{left:300,top:200});
 assert.deepEqual(at(pointer(8,8)),{left:8,top:8});
});

test('near the right edge the menu flips to the left of the pointer', () => {
 assert.deepEqual(at(pointer(1000,200)),{left:820,top:200});
});

test('near the bottom edge the menu flips up, above the pointer', () => {
 assert.deepEqual(at(pointer(300,700)),{left:300,top:460});
});

test('in the bottom-right corner it flips both ways', () => {
 assert.deepEqual(at(pointer(1000,700)),{left:820,top:460});
});

test('the keyboard menu opens just below the focused row, at its left edge', () => {
 assert.deepEqual(at(row(240,180,216)),{left:240,top:216});
});

test('a row near the bottom gets the menu ABOVE it, never over it', () => {
 // Flipped up from the row's own top, not from its bottom: the row the keys were
 // acting on stays visible.
 assert.deepEqual(at(row(240,700,736)),{left:240,top:460});
});

test('a menu that fits on neither side goes where there is more room, clamped', () => {
 // 500 px tall in a 600 px window, pointer in the middle: below has 292 px,
 // above has 292 px — neither fits, below is not roomier, so it stays below and
 // is pulled up until it fits.
 const tall = {width:180,height:500},small = {width:1024,height:600};
 assert.deepEqual(at(pointer(300,300),tall,small),{left:300,top:92});
 // Lower down, above is roomier: flipped, then clamped to the top margin.
 assert.deepEqual(at(pointer(300,450),tall,small),{left:300,top:8});
});

test('a menu larger than the viewport keeps its top-left corner on screen', () => {
 assert.deepEqual(at(pointer(50,50),{width:2000,height:2000}),{left:8,top:8});
});

test('an anchor outside the viewport is brought back inside it', () => {
 assert.deepEqual(at(pointer(-40,-40)),{left:8,top:8});
 assert.deepEqual(at(pointer(5000,5000)),{left:836,top:520});
});

test('the margin is a parameter, and fractions are rounded to whole pixels', () => {
 assert.deepEqual(menuPlacement({viewport,anchor:pointer(1000,700),menu,margin:0}),{left:820,top:460});
 assert.deepEqual(menuPlacement({viewport,anchor:pointer(300.6,200.4),menu}),{left:301,top:200});
});

test('nothing measured is nothing to place: garbage in, the margin out', () => {
 assert.deepEqual(menuPlacement(),{left:8,top:8});
 assert.deepEqual(menuPlacement({viewport:{width:'x'},anchor:{left:NaN},menu:{}}),{left:8,top:8});
});
