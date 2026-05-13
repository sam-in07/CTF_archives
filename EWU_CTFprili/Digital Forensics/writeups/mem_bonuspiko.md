# Mem - BonusPiko

**Category:** Memory Forensics
**Points:** 150
**Author:** 0xTrinity_Zer0

## Problem Description

When was the last time SlimShady updated the text in the Sticky Notes?

Flag format: `ROBOFEST{YYYY-MM-DD_HH:MM:SS}`

## Approach

1. Sticky Notes (Win7) stores its data in `%AppData%\Roaming\Microsoft\Sticky Notes\StickyNotes.snt` — an OLE2 compound document where each note is its own substorage. The substorage's modification time is updated whenever the note text changes; the Root Entry mtime tracks file open/close. So the *note storage* mtime is the answer, not the file mtime.

2. Locate the file in the dump and extract it via `windows.dumpfiles`:

   ```bash
   vol -f Shadow_Memory.raw windows.filescan | grep StickyNotes
   # 0x3fd40910  \Users\SlimShady\AppData\Roaming\Microsoft\Sticky Notes\StickyNotes.snt
   vol -f Shadow_Memory.raw -o /tmp/sn windows.dumpfiles --pid 2432
   ```

3. Parse the OLE container with `olefile` and read every directory entry's mtime:

   ```python
   import olefile
   f = olefile.OleFileIO('StickyNotes.snt.dat')
   for s in f.direntries:
       if s:
           print(s.name, s.getmtime(), s.getctime())
   # Root Entry                     2019-06-29 07:29:46.973  None
   # 20a0dcf6-98d9-11e9-9           2019-06-27 12:44:43.243  2019-06-27 12:44:43.227
   ```

   - `Root Entry` mtime (`2019-06-29 07:29:46`) is just when StikyNot.exe opened the file at session start — the dump time.
   - The note's GUID-named substorage `20a0dcf6-98d9-11e9-9` is what actually flips when text is edited: **`2019-06-27 12:44:43`**.

## Flag

```
ROBOFEST{2019-06-27_12:44:43}
```
