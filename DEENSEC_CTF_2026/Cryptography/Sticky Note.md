During a penetration test engagement, a network capture revealed a suspicious encrypted data stream. The hex dump was extracted from the packet payload:

0c0406051b0400303071311423723a143a7235787c2d702f35

Pinned to the suspect's monitor , in full view of the security camera , was a bright yellow sticky note. It read, in capital letters: 'HACK'.

Your incident report needs the decrypted plaintext.

Soln : 

The sticky note **"HACK"** is a strong hint that the payload was encrypted with a repeating-key XOR cipher using the key:

```text
HACK
```

Convert the hex string to bytes and XOR each byte with the corresponding byte of the repeating key:

```text
Ciphertext:
0c0406051b0400303071311423723a143a7235787c2d702f35

Key (repeating):
H A C K H A C K ...
```

Performing the XOR yields:

```text
DEENSEC{x0r_k3y_r3v34l3d}
```

**Decrypted plaintext / flag:**

```text
DEENSEC{x0r_k3y_r3v34l3d}
```

