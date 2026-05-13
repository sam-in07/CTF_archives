# Mem - The Last Note

**Category:** Memory Forensics
**Points:** 100
**Author:** 0xTrinity_Zer0

## Problem Description

On June 29, 2019, at 07:29 AM UTC, a memory image was captured from a Windows 7 workstation registered to a user known as **SlimShady**, a person of interest in an active digital investigation. The capture was performed using `DumpIt.exe`, a legitimate forensic tool, moments before the machine was remotely isolated.

Among the running processes, analysts noticed `StikyNot.exe` — Windows' sticky notes application. Nothing unusual about that. Except `StikyNot.exe` doesn't take command-line arguments. This one did.

**Examine the command line of StikyNot. What argument was passed to it?**

Attachment: `Shadow_Memory.7z` (extracts to `Shadow_Memory.raw`, ~1 GiB Windows 7 memory dump).

## Approach

1. Extract the archive:

   ```bash
   7z x Shadow_Memory.7z
   ```

2. Use Volatility 3 to dump the command line of every process and grep for `StikyNot`:

   ```bash
   vol -f Shadow_Memory.raw windows.cmdline.CmdLine | grep -i StikyNot
   ```

3. Output:

   ```
   2432   StikyNot.exe   "C:\Windows\System32\StikyNot.exe" /sticky:ROBOFEST{wh0_15_h1d1ng_1n_pl41n_s1ght}
   ```

PID 2432 ran with a non-standard `/sticky:` argument that contained the flag.

## Flag

```
ROBOFEST{wh0_15_h1d1ng_1n_pl41n_s1ght}
```
