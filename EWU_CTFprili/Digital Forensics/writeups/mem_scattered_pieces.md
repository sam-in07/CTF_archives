# Mem - Scattered Pieces

**Category:** Memory Forensics
**Points:** 500
**Author:** 0xTrinity_Zer0

## Problem Description

Sophisticated attackers don't store payloads in one place. They fragment them, splitting data across unrelated memory regions so that no single artifact reveals the full picture. A partial scan of `conhost.exe` found three distinct blobs of encoded data, each too short to be meaningful on its own. They are not random. They are pieces of a whole. Each fragment is labeled, each is encoded the same way.

Three encoded fragments are hidden in `conhost.exe` memory, each preceded by a labeled marker (`CTXBLK_A`, `CTXBLK_B`, `CTXBLK_C`). Decode each and assemble the flag in order.

## Approach

1. Locate every occurrence of the marker prefix `CTXBLK_` in the raw image:

   ```bash
   grep -aobF "CTXBLK_" Shadow_Memory.raw
   # 816764564:CTXBLK_   (B)
   # 816768660:CTXBLK_   (A)
   # 816776852:CTXBLK_   (C)
   ```

   Three hits, scattered (memory order is B, A, C — the labels are what dictate assembly order).

2. Each hit is laid out as `CTXBLK_X\0<payload>\0\0\0...`. The payload runs until the next null. Read each payload (skipping the 9-byte `CTXBLK_X\0` header):

   - A: `41 5C 51 5C 55 56 40 47 68 63 63`
   - B: `61 22 77 4C 60 63 23 23 75 22 7D`
   - C: `74 4C 77 20 67 20 70 67 20 77 6E`

3. The first byte of fragment A is `0x41` ('A'). If the decoded plaintext begins with `R` (the start of `ROBOFEST{`), the XOR key is `'A' ^ 'R' = 0x13`. Verify against the rest of A — every byte XORed with `0x13` yields printable ASCII spelling `ROBOFEST{pp`. ✓

4. Apply the same key to B and C, then concatenate in label order:

   ```python
   parts = {}
   with open('Shadow_Memory.raw','rb') as f:
       for label, off in [('A',816768660), ('B',816764564), ('C',816776852)]:
           f.seek(off + 9)               # skip "CTXBLK_X\0"
           body = f.read(64)
           body = body[:body.find(b'\x00')]
           parts[label] = bytes(b ^ 0x13 for b in body).decode()
   print(parts['A'] + parts['B'] + parts['C'])
   ```

   Output:

   ```
   A: ROBOFEST{pp
   B: r1d_sp00f1n
   C: g_d3t3ct3d}
   ```

   Concatenated → `ROBOFEST{ppr1d_sp00f1ng_d3t3ct3d}`.

## Flag

```
ROBOFEST{ppr1d_sp00f1ng_d3t3ct3d}
```