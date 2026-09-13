import {$,el,route} from './dom.js';
import {aclBadge} from './perm.js';
export const isSymlink = e => e.isSymlink || e.type === 'symlink';
export const hasTarget = e => !!(e.linkResolvedB64 || e.linkResolved);
export const isDirectory = e => isSymlink(e) ? hasTarget(e) && e.targetType === 'dir' : e.type === 'dir';
export const isReadable = e => isSymlink(e) ? hasTarget(e) && e.targetType === 'file' : e.type === 'file';
export const fileTarget = e => isSymlink(e) ? {path:e.linkResolved,pathB64:e.linkResolvedB64} : e;
export const actionHint = e => isSymlink(e) && !hasTarget(e) ? 'Symlink target is broken or unavailable.' : 'Only regular files can be viewed or downloaded.';
export function nameCell(entry) {
 const cell = el('span',{role:'gridcell',class:'name',title:entry.path});
 const glyph = entry.isSymlink ? '🔗' : isDirectory(entry) ? '📁' : entry.type === 'file' ? '📄' : '⚙';
 cell.append(el('span',{'aria-hidden':'true',class:'badge'},glyph));
 const broken = isSymlink(entry) && !hasTarget(entry);
 cell.append(el('span',{class:`nameText${broken ? ' broken' : ''}`},entry.name));
 if (entry.class === 'protected') cell.append(el('span',{class:'badge',title:'Protected system path','aria-label':'Protected system path'},'🛡'));
 // The ACL badge (M3 contract §6). It reports a STATE, not a boolean: every
 // object on a ZFS dataset carries system.nfs4_acl, so "the attribute exists"
 // would badge the entire NAS. A trivial NFSv4 ACL says exactly what the mode
 // says and gets no badge; an unreadable one gets the badge with the
 // pessimistic text, because a parse failure is never reported as "none".
 const acl = aclBadge(entry);
 if (acl) cell.append(el('span',{class:`badge acl acl-${acl.state}`,title:acl.title,'aria-label':acl.label},acl.glyph));
 if (entry.mountPoint) cell.append(el('span',{class:'badge',title:'Mount point','aria-label':'Mount point'},'⏏'));
 if (entry.isSymlink) cell.append(el('span',{class:'target'},`→ ${entry.linkTarget || '?'}${broken ? ' (broken)' : ''}`));
 return cell;
}
export function directoryNotice(page) {
 const text = [...(page.notes || [])];
 if (page.class === 'protected') text.unshift('🛡 Protected system path · read-only browse');
 $('#pathNotice').textContent = text.join(' · '); $('#pathNotice').hidden = !text.length;
}
export function volumeGroup(entries) {
 const volumes = entries.filter(e => e.volumeRoot);
 $('#mountGroup').hidden = volumes.length === 0;
 $('#mountLinks').replaceChildren(...volumes.map(e => el('a',{href:route(e)},'⏏ '+e.name)));
}
