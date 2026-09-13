import {api} from './api.js';
import {$,el,error,pathArgs,route} from './dom.js';
import {state,sessionGuard} from './state.js';
import {isDirectory,volumeGroup} from './badges.js';
let typeAhead='',typedAt=0;
// node renders one folder. ctx carries what used to be hard-wired to the
// sidebar, so the same renderer can be mounted anywhere (M2-B: the transfer
// dialog's destination picker): the container it lives in — keyboard navigation
// and the roving tabindex are scoped to it, never to #tree — what a pick DOES,
// and whether volume roots are offered as children (the sidebar hides them
// because volumeGroup lists them separately; a destination picker must be able
// to reach another volume).
function node(entry,level,ctx) {
 const item=el('div',{role:'treeitem','aria-level':level,'aria-expanded':'false',tabindex:'-1'});
 item.entry=entry; // so a caller can find a folder by path without parsing labels
 const line=el('div',{class:'treeLine'}), toggle=el('button',{tabindex:'-1','aria-label':'Expand '+entry.name},'▸'), label=el('button',{class:'treeLabel',tabindex:'-1'},entry.name+(entry.class==='protected' ? ' 🛡' : '')+(entry.isSymlink ? ' 🔗' : ''));
 line.append(toggle,label); item.append(line);
 let loaded=false;
 item.expand = async () => {
  const valid=sessionGuard();
  if (item.getAttribute('aria-expanded')==='true') { item.setAttribute('aria-expanded','false'); item.lastElementChild.hidden=true; toggle.textContent='▸'; return; }
  if (!loaded) {
   toggle.disabled=true;
   try {
    const group=el('div',{role:'group'});
    for (let offset=0;;) {
     const page=await api('api/fs/list',{...pathArgs(entry),offset,limit:500,sort:'name',hidden:state.hidden,volumes:false});
     if (!valid() || !item.isConnected || !state.session) return;
     for (const child of page.entries.filter(e => isDirectory(e) && (ctx.volumeRoots || !e.volumeRoot))) group.append(node(child,level+1,ctx));
     offset+=page.entries.length;
     if (!page.entries.length || offset>=page.total) break;
    }
    item.append(group); loaded=true;
   } catch(err) { if (valid() && item.isConnected) error(err); return; }
   finally { if (valid() && item.isConnected) toggle.disabled=false; }
  }
  item.setAttribute('aria-expanded','true'); item.lastElementChild.hidden=false; toggle.textContent='▾';
 };
 toggle.addEventListener('click',ev => { ev.stopPropagation(); item.expand().catch(error); });
 label.addEventListener('click',ev => { ev.stopPropagation(); ctx.onPick(entry,item); });
 item.addEventListener('focus',ev => { if (ev.target!==item) return; for (const other of ctx.container.querySelectorAll('[role=treeitem]')) other.tabIndex=-1; item.tabIndex=0; });
 item.addEventListener('keydown',ev => {
  if (ev.target!==item) return;
  const visible=[...ctx.container.querySelectorAll('[role=treeitem]')].filter(n => !n.closest('[hidden]'));
  const i=visible.indexOf(item);
  switch(ev.key) {
  case 'ArrowDown': visible[Math.min(i+1,visible.length-1)]?.focus(); break;
  case 'ArrowUp': visible[Math.max(0,i-1)]?.focus(); break;
  case 'Home': visible[0]?.focus(); break;
  case 'End': visible.at(-1)?.focus(); break;
  case 'ArrowRight': if (item.getAttribute('aria-expanded')==='false') item.expand().catch(error); else item.querySelector('[role=group] > [role=treeitem]')?.focus(); break;
  case 'ArrowLeft': if (item.getAttribute('aria-expanded')==='true') item.expand().catch(error); else item.parentElement.closest('[role=treeitem]')?.focus(); break;
  case 'Enter': label.click(); break;
  case ' ': item.expand().catch(error); break;
  default:
   if (ev.key.length===1 && !ev.ctrlKey && !ev.altKey) { typeAhead=Date.now()-typedAt>700 ? ev.key : typeAhead+ev.key; typedAt=Date.now(); visible.find(n => n.querySelector('.treeLabel').textContent.toLowerCase().startsWith(typeAhead.toLowerCase()))?.focus(); }
   return;
  }
  ev.preventDefault(); ev.stopPropagation();
 });
 return item;
}

// ancestorChain is "/share/Public/Docs" → ["/share","/share/Public",
// "/share/Public/Docs"]: the folders that have to be opened, in order, for that
// path to be on screen. Pure, and empty for anything that is not absolute.
export function ancestorChain(path) {
 const p=String(path||'');
 if (!p.startsWith('/')) return [];
 const out=[];
 let at='';
 for (const part of p.split('/').filter(Boolean)) { at+='/'+part; out.push(at); }
 return out;
}

// renderTree paints a folder tree into container and opens it down to expandTo.
// onPick(entry,item) is what activating a folder does — the sidebar navigates,
// the transfer picker selects a destination. It resolves to the deepest item it
// managed to open (the root when expandTo is not reachable), or null when the
// session moved on underneath it.
export async function renderTree({container,onPick,expandTo='',volumeRoots=false}) {
 const valid=sessionGuard();
 const ctx={container,onPick,volumeRoots};
 container.replaceChildren();
 const root=node({name:'/',path:'/',type:'dir'},1,ctx); root.tabIndex=0; container.append(root);
 await root.expand();
 if (!valid() || !root.isConnected) return null;
 // Each step needs its parent's children loaded, so the chain is walked one
 // level at a time; a missing link (hidden, unreadable, gone) simply stops the
 // descent rather than failing the render.
 let deepest=root;
 for (const path of ancestorChain(expandTo)) {
  const next=[...deepest.querySelectorAll(':scope > [role=group] > [role=treeitem]')].find(n => n.entry?.path===path);
  if (!next) break;
  if (next.getAttribute('aria-expanded')==='false') await next.expand();
  if (!valid() || !root.isConnected) return null;
  deepest=next;
 }
 return deepest;
}

// navigateTo is the sidebar's pick: go there, and close the drawer on narrow
// screens where the tree overlays the list.
function navigateTo(entry) {
 location.hash=route(entry);
 $('#tree').classList.remove('open');
 $('#btnTree').setAttribute('aria-expanded','false');
}

export async function loadTree() {
 if (!state.session) return;
 const valid=sessionGuard();
 const tree=$('#tree');
 try {
  // /share is opened for the same reason it always was: it is where everything
  // a user recognises lives, and the root alone shows nothing useful.
  const opened=await renderTree({container:tree,onPick:navigateTo,expandTo:'/share'});
  if (!valid() || !opened || !opened.isConnected) return;
  const roots=await api('api/fs/roots');
  if (!valid() || !opened.isConnected || !state.session) return;
  volumeGroup(roots);
 } catch(err) { if (valid()) error(err); }
}
