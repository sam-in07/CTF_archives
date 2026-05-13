# Mem - Ghost in the Drive

**Category:** Memory Forensics
**Points:** 150
**Author:** 0xTrinity_Zer0

## Problem Description

The machine belonging to SlimShady had been under surveillance for some time before this capture was taken. Investigators suspect this wasn't the first time someone had imaged this machine. A previous memory capture is sitting somewhere on the filesystem — still referenced in memory, never deleted. Find it before someone else does.

Locate it and submit its filename as the flag.

## Approach

1. First instinct — `windows.filescan` for any `_FILE_OBJECT` with a memory-image extension:

   ```bash
   vol -f Shadow_Memory.raw windows.filescan | grep -iE '\.(raw|mem|vmem|dmp)$'
   # \Users\eminem\Desktop\DumpIt\2PAC-20190629-072925.raw
   ```

   That single hit (`2PAC-20190629-072925.raw`, timestamp `20190629-072925`) is the **current** capture — its filename embeds the same time the dump was taken. Not the answer. The previous capture's `_FILE_OBJECT` is no longer cached.

2. Fall back to raw `strings` — old filenames often linger in DumpIt's process heap, MFT entries, prefetch, and shellbag artifacts long after the file itself stops being open:

   ```bash
   strings -a Shadow_Memory.raw | grep -iE '[A-Za-z0-9_-]+\.(raw|mem|vmem|dmp)$' | sort -u
   ```

   Two `2PAC-*.raw` filenames show up:

   ```
   2PAC-20190625-132823.raw   ← previous capture (June 25, 13:28:23)
   2PAC-20190629-072925.raw   ← current capture (June 29, 07:29:25)
   ```

   The June 25 entry is the residue the challenge is pointing at — DumpIt remembered the prior run.

## Flag

```
2PAC-20190625-132823.raw
```