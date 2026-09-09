const listeners = new Set();
export const state = {session:null,path:'/share',pathB64:'',sort:'name',desc:false,hidden:false,total:0,pages:new Map(),selection:new Set(),exclude:false,focus:0,anchor:0,filter:'',generation:0,loading:false};
export function update(patch) { Object.assign(state,patch); for (const fn of listeners) fn(state); }
export function subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); }
export const selected = index => state.exclude !== state.selection.has(index);
export const countSelected = () => state.exclude ? Math.max(0,state.total-state.selection.size) : state.selection.size;
