# Mem - Ready to Send

**Category:** Memory Forensics
**Points:** 400
**Author:** 0xTrinity_Zer0

## Problem Description

The final stage of a data theft attack is exfiltration — moving stolen data off the compromised machine. Before a connection can be established to the attacker's server, the data must first be staged in memory: packaged, encoded, and held ready. A memory region associated with `conhost.exe` contains what appears to be a system log entry. It isn't. It's staged exfiltration data, encoded in the most widely used binary-to-text encoding scheme on the internet (Base64). The network connection was cut before it could be sent — but the data is still there.

## Approach

The hint tells us exactly what to look for: a Base64 blob disguised as a system log line. Skip the per-process VAD dance and grep the entire raw image for any Base64 substring that decodes to text containing `ROBOFEST`:

```python
import re, base64
data = open('Shadow_Memory.raw', 'rb').read()
for m in re.finditer(rb'[A-Za-z0-9+/]{16,}={0,2}', data):
    b = m.group()
    if len(b) % 4 != 0:
        continue
    try:
        ds = base64.b64decode(b).decode('utf-8')
        if 'ROBOFEST' in ds:
            print(m.start(), b, ds)
    except Exception:
        pass
```

Single hit at offset `817067678`:

```
b64: Uk9CT0ZFU1R7YjRzMzY0XzFuX20zbTByeV8zeGYxbH0=
dec: ROBOFEST{b4s364_1n_m3m0ry_3xf1l}
```

Reading 80 bytes of context confirms the disguise — the Base64 was prefixed with a fake syslog tag:

```
[SYSLOG]: Uk9CT0ZFU1R7YjRzMzY0XzFuX20zbTByeV8zeGYxbH0=\n
```

That's exactly what you'd expect for staged exfiltration that wants to blend into log-ingestion noise.

## Flag

```
ROBOFEST{b4s364_1n_m3m0ry_3xf1l}
```
