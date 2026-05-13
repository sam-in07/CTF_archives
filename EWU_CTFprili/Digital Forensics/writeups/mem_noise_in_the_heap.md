# Mem - Noise in the Heap

**Category:** Memory Forensics
**Points:** 400
**Author:** 0xTrinity_Zer0

## Problem Description

`explorer.exe` is the beating heart of the Windows desktop — always running, always trusted. Malware has long exploited this trust by injecting payloads into its memory. A region inside `explorer.exe` was flagged by the analysis pipeline as anomalous. The bytes didn't match any known code or data pattern. To a casual observer, it looks like random garbage. To someone who knows what to look for, it's a message waiting to be decoded.

A blob of obfuscated data was found inside `explorer.exe` memory. The encoding uses a single-byte repeating key. Recover the original content.

## Approach

1. Identify `explorer.exe` PIDs in the memory image:

   ```bash
   vol -f Shadow_Memory.raw windows.pslist | grep explorer
   # 1944  explorer.exe  ...
   # 3012  explorer.exe  ...
   ```

2. Dump every VAD region for the main `explorer.exe` (PID 1944) so each can be searched independently:

   ```bash
   mkdir -p /tmp/exp_dump
   vol -f Shadow_Memory.raw -o /tmp/exp_dump windows.vadinfo --pid 1944 --dump
   ```

3. Brute-force a single-byte XOR over each dumped region, looking for the well-known flag prefix `ROBOFEST` after decoding:

   ```python
   import os
   target = b'ROBOFEST'
   for fn in sorted(os.listdir('.')):
       if not fn.endswith('.dmp'): continue
       data = open(fn, 'rb').read()
       for k in range(1, 256):
           pat = bytes(b ^ k for b in target)
           if pat in data:
               idx = data.find(pat)
               ctx = data[max(0, idx-8):idx+80]
               print(fn, hex(k), bytes(b ^ k for b in ctx))
               break
   ```

4. Hit:

   ```
   pid.1944.vad.0x7fefdee0000-0x7fefdf7efff.dmp  key=0x41
   ctx: b'...ROBOFEST{dll_p4th_r3v34ls_th3_truth}AAAAAAAAA...'
   ```

   The XOR key is `0x41` (ASCII `'A'`). The trailing run of `'A'` bytes is exactly what you'd expect when the original buffer was zero-padded — XOR with `0x41` turns null padding into `'A'`, which is also a giveaway for the key.

5. The host VAD (`0x7fefdee0000`) maps to `msvcrt.dll`, so the obfuscated blob was stashed inside an unused/zero-padded slack region of `msvcrt.dll`'s mapping in `explorer.exe` — fitting the challenge's "looks like random garbage" framing.

## Flag

```
ROBOFEST{dll_p4th_r3v34ls_th3_truth}
```
