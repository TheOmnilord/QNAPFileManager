import {api} from './api.js';
import {$,el,error,pathArgs,route} from './dom.js';
import {state,sessionGuard} from './state.js';
import {isDirectory,volumeGroup} from './badges.js';
let typeAhead='',typedAt=0,moreSeq=0;

// An expansion reads ONE page (stabilization contract §4.2). It used to read
// every page of the folder to find the subfolders among its files — a folder
// of 200,000 files was 400 requests before one arrow turned. It asks for
// dirsFirst instead, so the server lists every folder before any file, and the
// first page holds all of them unless it holds nothing else.
export const TREE_PAGE=500;
export const TREE_MORE='More entries are not shown — open this folder.';

// treeContinues says whether the page can be hiding folders: only when it is
// full, every entry in it is a folder, and the folder holds more than it. A
// page with a single file in it already holds every folder there is. "Folder"
// is the server's own word for ordering, type "dir"; a symlink to a folder
// sorts among the files (contract §1.2). So one that sorts after the first page
// is not offered here, and nothing says so — the listing and the path field
// still reach it. `limit` is the page size the server actually used, which a
// configured ListMax can make smaller than the one asked for.
export function treeContinues(page,requested=TREE_PAGE) {
 const entries=page?.entries || [];
 const limit=Number(page?.limit) || requested;
 return entries.length>0 && entries.length>=limit && Number(page?.total)>entries.length && entries.every(e => e.type==='dir');
}

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
    const page=await api('api/fs/list',{...pathArgs(entry),limit:TREE_PAGE,sort:'name',dirsFirst:true,hidden:state.hidden,volumes:false});
    if (!valid() || !item.isConnected || !state.session) return;
    const group=el('div',{role:'group'});
    for (const child of (page.entries || []).filter(e => isDirectory(e) && (ctx.volumeRoots || !e.volumeRoot))) group.append(node(child,level+1,ctx));
    // The continuation is a plain line, not a treeitem, so the arrow keys pass
    // it by. A screen reader that never lands on it still hears it: the folder
    // it belongs to is described by it.
    if (treeContinues(page)) {
     const more=el('div',{class:'treeMore',id:`treeMore-${++moreSeq}`},TREE_MORE);
     group.append(more);
     item.setAttribute('aria-describedby',more.id);
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
