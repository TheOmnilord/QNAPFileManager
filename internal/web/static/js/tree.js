import {api} from './api.js';
import {$,el,error,pathArgs,route} from './dom.js';
import {state,sessionGuard} from './state.js';
import {isDirectory,volumeGroup} from './badges.js';
let typeAhead='',typedAt=0;
function node(entry,level) {
 const item=el('div',{role:'treeitem','aria-level':level,'aria-expanded':'false',tabindex:'-1'});
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
     for (const child of page.entries.filter(e => isDirectory(e) && !e.volumeRoot)) group.append(node(child,level+1));
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
 label.addEventListener('click',ev => { ev.stopPropagation(); location.hash=route(entry); $('#tree').classList.remove('open'); $('#btnTree').setAttribute('aria-expanded','false'); });
 item.addEventListener('focus',ev => { if (ev.target!==item) return; for (const other of $('#tree').querySelectorAll('[role=treeitem]')) other.tabIndex=-1; item.tabIndex=0; });
 item.addEventListener('keydown',ev => {
  if (ev.target!==item) return;
  const visible=[...$('#tree').querySelectorAll('[role=treeitem]')].filter(n => !n.closest('[hidden]'));
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

export async function loadTree() {
 if (!state.session) return;
 const valid=sessionGuard();
 const tree=$('#tree'); tree.replaceChildren();
 const root=node({name:'/',path:'/',type:'dir'},1); root.tabIndex=0; tree.append(root);
 try {
  await root.expand();
  if (!valid() || !root.isConnected) return;
  const share=[...root.querySelectorAll('[role=treeitem]')].find(n => n.querySelector('.treeLabel').textContent==='share');
  if (share) await share.expand();
  if (!valid() || !root.isConnected) return;
  const roots=await api('api/fs/roots');
  if (!valid() || !root.isConnected || !state.session) return;
  volumeGroup(roots);
 } catch(err) { if (valid() && root.isConnected) error(err); }
}
