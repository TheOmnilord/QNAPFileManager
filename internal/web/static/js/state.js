const listeners = new Set();
export const state = {session:null,sessionGeneration:0,path:'/share',pathB64:'',sort:'name',desc:false,hidden:false,total:0,pages:new Map(),selection:new Set(),exclude:false,focus:0,anchor:0,filter:'',generation:0,loading:false};
// Capture before awaiting: even signing back in as the same user invalidates old work.
export function sessionGuard() { const generation=state.sessionGeneration; return () => generation===state.sessionGeneration; }
export function update(patch) {
 if (Object.hasOwn(patch,'session')) state.sessionGeneration++;
 Object.assign(state,patch);
 for (const fn of listeners) fn(state);
}
export function subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); }
export const selected = index => state.exclude !== state.selection.has(index);
export const countSelected = () => state.exclude ? Math.max(0,state.total-state.selection.size) : state.selection.size;
