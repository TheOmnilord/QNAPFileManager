import {$,el,route} from './dom.js';
export const isDirectory = e => e.type === 'dir' || e.targetType === 'dir';
export const isReadable = e => e.type === 'file' || e.targetType === 'file';
export function nameCell(entry) {
 const cell = el('span',{role:'gridcell',class:'name',title:entry.path});
 const glyph = entry.isSymlink ? '🔗' : isDirectory(entry) ? '📁' : entry.type === 'file' ? '📄' : '⚙';
 cell.append(el('span',{'aria-hidden':'true',class:'badge'},glyph));
 const broken = entry.isSymlink && !entry.targetType;
 cell.append(el('span',{class:`nameText${broken ? ' broken' : ''}`},entry.name));
 if (entry.class === 'protected') cell.append(el('span',{class:'badge',title:'Protected system path','aria-label':'Protected system path'},'🛡'));
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
