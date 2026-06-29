This image came off the main controller of a unit that kept operating long after it was supposedly shut down. The vendor built the firmware to resist anyone taking it apart, load it into your tools and the routine at its heart reads like deliberate static. Buried somewhere inside is a factory service credential that was never meant to ship on production hardware. Recover it, and you'll have your first answer about what this machine really was.


Soln : 
Solver : [sam_in_Ironside](https://github.com/sam-in07)
 # Self-Decrypting Firmware Write-up

## Challenge Overview

The challenge provides a firmware binary extracted from the main controller of a device. During analysis, the binary appears heavily obfuscated because the actual verification logic is not stored in plaintext. Instead, it decrypts executable code at runtime before validating the user input.

The goal is to reverse this verification routine and recover the hidden factory service credential.

---

## Step 1: Analyze the Main Function

The core logic is located in `FUN_00101170`.

The function performs the following operations:

1. Reads a **38-character** (`0x26`) input string from the user.
2. Allocates executable memory using `mmap()`.
3. Copies **90 bytes** (`0x5a`) of encrypted shellcode from `DAT_001020a0`.
4. XOR-decrypts the shellcode using the key `0x7c`.
5. Changes the memory permissions with `mprotect()` to make it executable.
6. Executes the decrypted shellcode, passing:

   * the user input
   * an encrypted verification table stored at `DAT_00102060`

At this point, the real flag verification happens inside the decrypted shellcode rather than in the original binary.

---

## Step 2: Analyze the Decrypted Shellcode

After decrypting the shellcode, the verification algorithm becomes clear.

For every character `i` (from **0** to **37**), the shellcode computes:

```text
target[i] = ((i + 0x5A) XOR ROL8(input[i], 3)) + (7 × i) mod 256
```

where:

* `ROL8()` is an 8-bit left rotation.
* `target[]` is the encrypted verification table.

If every computed value matches the corresponding byte in the target array, the input is accepted.

---

## Step 3: Reverse the Algorithm

To recover the original input, we simply reverse each operation.

For each index `i`:

1. Remove the index-dependent offset:

```text
temp = (target[i] - 7 × i) mod 256
```

2. Undo the XOR operation:

```text
val = temp XOR (i + 0x5A)
```

3. Reverse the left rotation by performing a right rotation:

```text
input[i] = ROR8(val, 3)
```

Applying these steps to every byte in the target array reconstructs the original credential.

---

## Recovered Flag

```text
ROBOFEST{s3lf_d3crypt1ng_c0d3_runt1m3}
```

---

## Conclusion

This challenge uses **runtime code decryption** to hide its verification logic from static analysis. Instead of storing the checking routine directly in the binary, it decrypts shellcode in memory, marks it executable, and then transfers execution to it.

Once the shellcode was decrypted, the verification algorithm was straightforward to analyze. By reversing the arithmetic operations, XOR, and bit rotations, the original factory service credential could be recovered successfully.

**Final Flag**

```text
ROBOFEST{s3lf_d3crypt1ng_c0d3_runt1m3}
```
