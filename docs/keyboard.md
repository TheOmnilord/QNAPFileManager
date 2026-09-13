# Keyboard map

The same map the app shows in its **shortcuts dialog**, which you open with `?`.

The dialog is authoritative, and deliberately so: `internal/web/static/js/keys.js` holds the map and the handler's
binding table in one file, and a node test cross-checks them against each other and against the embedded HTML. A shortcut
cannot be added, removed or re-bound without the dialog changing. This page and the README mirror it for people who
cannot open the app; if they ever disagree with the dialog, they are the ones that are wrong.

**Every shortcut has a mouse equivalent.** The app runs inside the QTS desktop, which swallows some chords, so no action
is reachable only by keyboard. `Ctrl+R` is never intercepted — it is the browser's own reload and stays that way.

## In the file list

| Keys | What it does |
|---|---|
| `↑` `↓` | move the focused row |
| `Home` / `End` | first or last row |
| `Page Up` / `Page Down` | move a screen at a time |
| `Shift` + movement | extend the selection |
| `Ctrl` + movement | move without changing the selection |
| `Space` | select or deselect the focused row |
| `Ctrl+A` | select everything in this folder |
| `Enter` | open the folder or file |
| `Alt+Enter` | properties |
| `F4` | view the file as text |
| `Shift+F10` / `Menu` | actions for the focused row |
| `Esc` | clear the selection |
| type a name | jump to the first loaded match |

## Anywhere in the app

| Keys | What it does |
|---|---|
| `Delete` | move the selection to Trash |
| `F9` | permissions |
| `Ctrl+C` | mark the selection to copy |
| `Ctrl+X` | mark the selection to move |
| `Ctrl+V` | paste into this folder |
| `Ctrl+F` | search this folder and below |
| `Ctrl+L` | edit the path |
| `/` | filter the names loaded so far |
| `Ctrl+H` | show or hide hidden items |
| `Backspace` | go to the parent folder |
| `Alt+←` / `Alt+→` | back / forward |
| `F5` | refresh this folder |
| `Esc` | close the results, the actions menu or the folder drawer |
| `?` | open this keyboard map |

## The browser's own

| Keys | What it does |
|---|---|
| `Ctrl+R` | reload the page — always the browser's, never intercepted |

## Notes

- `Ctrl` and `Cmd` are the same chord, so a Mac user's `Cmd+C` is a copy.
- `Ctrl+F` is the app's **subtree search**, not the browser's find-in-page. On a virtualised listing of a million files,
  find-in-page could only ever search the rows currently painted. Like `Ctrl+L`, it works from inside the filter box.
- `Ctrl+C` with text selected leaves the keys to the browser — you are copying text, not files.
- `Delete`, `Ctrl+C`, `Ctrl+X` and `Ctrl+V` act on the *listing's* selection. While search results are covering the
  listing they do nothing and say so once, rather than silently acting on rows nobody can see. Press `Esc` to close the
  results first.
- No shortcut fires while a dialog is open or while you are typing in a field, except the two marked above as working
  from the filter box.

## Not bound in 1.0

The design's shortcut table (`ui-ux-safety-plan` §3.9) also lists `Ctrl+Shift+N` for a new folder, `F2` for rename and
`Shift+Del` for permanent delete. They are **not bound** in 1.0 and so are not in the dialog or in the tables above. All
three actions are reachable from the toolbar and the context menu; permanent delete is also offered as a choice in the
delete confirmation.
