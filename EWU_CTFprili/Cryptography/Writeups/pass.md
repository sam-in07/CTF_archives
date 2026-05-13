# Password Challenge

- **Category:** crypto / misc
- **Service:** `nc 160.187.130.156 27774`
- **Flag:** `ROBOFEST{h4sh1ng_1s_th3_k3y_t0_s3cur1ty}`

## Description

The remote service streams a sequence of password hashes and asks you to type
the original plaintext for each one:

```
Hash : 895d1ba9ca06739e53361d66a06042cdc037ef6d8db8056d38e3aca23c1c9644
Your guess for the original password: viper
✓ Correct!
```

Hashes are mixed: 32-hex MD5, 40-hex SHA1, and 64-hex SHA256. After enough
correct answers in a row the server prints the flag. **Any wrong answer
disconnects you immediately**, so the run must be perfect.

## Approach

The plaintexts are common passwords (`viper`, `falcon`, `pass1234`, …), which
is the unmistakable signature of a rockyou-style wordlist. So:

1. Precompute MD5/SHA1/SHA256 of every password in `rockyou.txt` into three
   in-memory dicts (hash → password) and pickle them to disk.
2. Read each `Hash : …` line, pick the algorithm by hex length
   (`32 → md5`, `40 → sha1`, `64 → sha256`), look up the answer, send it.
3. Because one miss kills the connection, wrap the whole session in a retry
   loop. Each connection is a fresh random sample of hashes, and rockyou
   coverage isn't 100%, so just reconnect on miss until a session is fully
   covered.

### One-time DB build (`build_hash_db.py`)

```python
import hashlib, pickle
md5, sha1, sha256 = {}, {}, {}
with open("rockyou.txt", "rb") as f:
    for line in f:
        pw = line.rstrip(b"\r\n")
        if not pw:
            continue
        md5[hashlib.md5(pw).hexdigest()]      = pw
        sha1[hashlib.sha1(pw).hexdigest()]    = pw
        sha256[hashlib.sha256(pw).hexdigest()] = pw
pickle.dump({"md5": md5, "sha1": sha1, "sha256": sha256},
            open("rockyou_hashes.pkl", "wb"),
            protocol=pickle.HIGHEST_PROTOCOL)
```

~30s on a laptop, ~2.4 GB pickle file, 14.3M unique passwords per algorithm.

### Solver core

```python
ALGO_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
HASH_RE = re.compile(rb"Hash\s*:\s*([0-9a-fA-F]+)")

def play_one_session(db):
    io = remote("160.187.130.156", 27774)
    try:
        while True:
            chunk = io.recvuntil(b"password:", timeout=15)
            m = HASH_RE.search(chunk)
            if not m:                          # server is done talking
                return True, io.recvrepeat(2)
            h = m.group(1).decode().lower()
            pw = db[ALGO_BY_LEN[len(h)]].get(h)
            if pw is None:                     # rockyou miss → bail and retry
                io.sendline(b"?")
                return False, b""
            io.sendline(pw)
    finally:
        io.close()
```

Wrap that in a `for attempt in range(40): ...` until `play_one_session`
returns success.

## Result

Attempt 3 came up clean: 50 hashes solved without a miss, and the server
emitted the flag at the end:

```
Hash : 51977f38bb3afdf634dd8162c7a33691
Your guess for the original password: ✓ Correct!

Your flag: ROBOFEST{h4sh1ng_1s_th3_k3y_t0_s3cur1ty}
```

**Flag:** `ROBOFEST{h4sh1ng_1s_th3_k3y_t0_s3cur1ty}`