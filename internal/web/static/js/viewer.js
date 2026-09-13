import {api,apiURL} from './api.js';
import {$,el,pathArgs,openDialog,error} from './dom.js';
import {isReadable,fileTarget} from './badges.js';
import {sessionGuard} from './state.js';
let current;
export function download(entry) {
 if (!entry || !isReadable(entry)) return;
 fetchThrough(apiURL('api/fs/download',pathArgs(fileTarget(entry))),entry.name);
}

// fetchThrough is how every download leaves this app: an anchor with a download
// name, clicked and removed. There is no fetch — the browser owns the transfer,
// shows its own progress and writes the file where the user keeps files, none
// of which a page can do for a multi-gigabyte archive.
function fetchThrough(href,name) {
 const link = el('a',{href,download:name});
 document.body.append(link); link.click(); link.remove();
}

// --- archive download (M2-C, contract §2.4) ----------------------------------

// FORMATS maps the wire's format to the extension a user expects to see.
export const FORMATS = {zip:'.zip',tgz:'.tar.gz'};

// NAME_MAX is the kernel's limit on one path component, in bytes. It is the
// budget the whole generated name has to fit inside — extension included.
export const NAME_MAX = 255;

// A name is measured in BYTES, which is what the limit counts — not in
// JavaScript characters.
const byteLength = text => new TextEncoder().encode(String(text ?? '')).length;

// truncateBytes cuts text to at most max BYTES without splitting a character.
//
// Slicing by JavaScript characters would not do: a name is UTF-8 on the wire
// and one character can be four bytes. Cutting mid-sequence produces a name
// whose last character is U+FFFD — a different name, and one the user never
// had. So the cut backs off over any UTF-8 continuation byte (10xxxxxx) to the
// nearest character boundary, and whole code points are all that survive.
export function truncateBytes(text,max) {
 const value = String(text ?? '');
 const bytes = new TextEncoder().encode(value);
 if (bytes.length <= max) return value;
 let end = Math.max(0,max);
 while (end > 0 && (bytes[end] & 0xc0) === 0x80) end--;
 return new TextDecoder().decode(bytes.subarray(0,end));
}

// archiveName is what the browser saves the stream as. One selected item lends
// the archive its own name — downloading the folder "Photos" should produce
// "Photos.zip" and not something generic — while a mixed selection has no name
// of its own to borrow and gets the neutral one.
//
// The borrowed name is BOUNDED. A file may legitimately be named up to 255
// bytes, and appending ".tar.gz" to one of those made a name of 262 bytes that
// the route refused outright, so downloading a folder with a long name simply
// failed (round 6, finding 3). The base is trimmed to leave room for the
// extension; if nothing usable survives, the neutral name is used instead.
export function archiveName(entries,format) {
 const list = Array.isArray(entries) ? entries : [];
 const ext = FORMATS[format] || FORMATS.zip;
 const one = list.length === 1 ? String(list[0]?.name || '') : '';
 return (truncateBytes(one,NAME_MAX-byteLength(ext)) || 'archive') + ext;
}

// archiveURL is the streaming download's address. Every root is repeated as its
// OWN parameter, in the same two spellings every path travels in: pathB64 where
// the entry carries authoritative bytes, path otherwise — a selection may well
// mix the two, and the array-of-pairs form is the only one that can express a
// repeated key.
//
// crossMounts is passed in rather than decided here: whether a hero volume's
// mounted sub-folders belong inside the archive is a question about the user's
// preference, not about URL building.
export function archiveURL(entries,format,opts = {}) {
 const pairs = [];
 for (const entry of Array.isArray(entries) ? entries : []) {
  if (!entry) continue;
  if (entry.pathB64) pairs.push(['pathB64',entry.pathB64]);
  else pairs.push(['path',String(entry.path ?? '')]);
 }
 pairs.push(['format',FORMATS[format] ? format : 'zip']);
 pairs.push(['name',opts.name || archiveName(entries,format)]);
 if (opts.crossMounts) pairs.push(['crossMounts','1']);
 return apiURL('api/fs/archive',pairs);
}

// downloadMode is what the Download button means for the current selection: a
// single readable FILE is a plain download (the same bytes, no container); a
// folder, or more than one item, can only leave as an archive. Nothing selected
// is nothing to download. Pure, so the toolbar's three states are tested rather
// than inferred from a screenshot.
export function downloadMode({count,entry} = {}) {
 const n = Number(count) || 0;
 if (n < 1) return 'none';
 if (n === 1 && entry && isReadable(entry)) return 'file';
 return 'archive';
}

// --- the selection ticket ----------------------------------------------------

// ARCHIVE_URL_LIMIT is the point past which the selection stops travelling in
// the URL and travels in a request BODY instead.
//
// An archive names every root as its own query parameter, so a selection of a
// few hundred files — ordinary on a NAS — writes a GET request line of tens of
// kilobytes. The server caps request headers at 64 KiB and answers 431 before
// the handler ever runs, which arrives as a download that simply does not
// happen. 8 KiB is deliberately far below the cap: the request line is not the
// only header, the QTS reverse proxy has limits of its own, and a percent-
// encoded non-UTF-8 name costs three characters a byte.
export const ARCHIVE_URL_LIMIT = 8192;

// archiveNeedsTicket says whether this download has to be arranged in two steps.
// A URL is measured in bytes too (byteLength, above).
export function archiveNeedsTicket(url) { return byteLength(url) > ARCHIVE_URL_LIMIT; }

// archiveTicketRequest is the POST body that buys a ticket: the same selection
// archiveURL would have spelled into the query, in the pathRef shape every
// other mutation uses.
export function archiveTicketRequest(entries,format,opts = {}) {
 const list = (Array.isArray(entries) ? entries : []).filter(Boolean);
 const body = {paths:list.map(pathArgs),format:FORMATS[format] ? format : 'zip',name:opts.name || archiveName(list,format)};
 if (opts.crossMounts) body.crossMounts = true;
 return body;
}

// archiveTicketURL is the second step: one short, opaque, single-use token in
// place of the whole selection.
export function archiveTicketURL(token) { return apiURL('api/fs/archive',[['sel',String(token ?? '')]]); }

// downloadArchive streams a selection as one archive. Small selections go
// straight out as a GET — one request, no server-side state, nothing to expire.
// Only a selection too large for a URL pays for the ticket.
export async function downloadArchive(entries,format,opts = {}) {
 const list = (Array.isArray(entries) ? entries : []).filter(Boolean);
 if (!list.length) return;
 const name = archiveName(list,format),direct = archiveURL(list,format,opts);
 if (!archiveNeedsTicket(direct)) { fetchThrough(direct,name); return; }
 const valid = sessionGuard();
 try {
  const res = await api('api/fs/archive/select',{},{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify(archiveTicketRequest(list,format,opts))});
  if (!valid()) return;
  if (!res?.sel) throw new Error('The download could not be prepared. Try again, or select fewer items.');
  // The ticket is single use and short lived, so it is spent immediately.
  fetchThrough(archiveTicketURL(res.sel),name);
 } catch(err) { if (valid()) error(err); }
}
export async function view(entry) {
 if (!entry || !isReadable(entry)) return;
 const valid=sessionGuard();
 current = entry; $('#viewerTitle').textContent = entry.path;
 $('#viewerContent').textContent = 'Loading…'; $('#viewerNote').textContent = 'Read-only'; openDialog('#dlgViewer');
 try {
  const data = await api('api/fs/text',pathArgs(fileTarget(entry)));
  if (!valid() || !$('#dlgViewer').open || current !== entry) return;
  $('#viewerContent').textContent = data.binary ? 'This file contains binary data. Download it to view it in another application.' : data.content;
  $('#viewerNote').textContent = `${data.bytes.toLocaleString()} bytes · ${data.mode} · read-only${data.truncated ? ' · Preview truncated' : ''}`;
 } catch(err) { if (valid() && $('#dlgViewer').open && current === entry) { $('#viewerContent').textContent = err.message; error(err); } }
}
// propsEntry is what the Properties dialog is currently showing, so "Calculate
// size" (jobs.js) knows what to measure without viewer.js importing the job
// module — which would close an import cycle through list.js.
let propsEntry = null;
export const propsTarget = () => propsEntry;
export async function properties(entry) {
 if (!entry) return;
 const valid=sessionGuard();
 try {
  const data = await api('api/fs/stat',pathArgs(entry));
  if (!valid()) return;
  propsEntry = entry;
  $('#propsContent').textContent = Object.entries(data).map(([k,v]) => `${k}: ${v}`).join('\n');
  $('#propsSize').textContent = ''; $('#btnCalcSize').disabled = false;
  openDialog('#dlgProps');
 } catch(err) { if (valid()) error(err); }
}
export function initViewer() { $('#viewerDownload').addEventListener('click',() => download(current)); }
