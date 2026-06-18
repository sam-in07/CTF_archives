A suspicious internal security report was distributed across the department.

At first read, it is a perfectly reasonable write-up about password hygiene and two-factor authentication. Grammatically correct. Professionally written. Utterly mundane.

But an analyst who processed it noticed something: "The line lengths are odd. Some lines end awkwardly, like the last word was forced in. Maybe they weren't thinking about how lines end… or maybe they were thinking about nothing else."

Download : memo.txt

What can this be really hidding? (Flag Format : DEENSEC{ ... })



soln ::


The hint is pointing to something hidden in the **line endings / last characters of each line**:

> “The line lengths are odd… maybe the last word was forced in”

So we look at the **last character of each meaningful line** (excluding the divider lines).

Extract the final characters:

```
D
E
E
N
S
E
C
l
4
s
t
L
3
t
t
3
N
```

Now we clean it up logically:

* First 7 characters clearly form the prefix:

  ```
  DEENSEC
  ```

* The remaining characters:

  ```
  l 4 s t L 3 t t 3 N
  ```

Now interpret leetspeak + capitalization noise:

* l → l
* 4 → a
* s → s
* t → t
* L → l
* 3 → e
* t → t
* t → t
* 3 → e
* N → n

This becomes:

```text
lastlettern
```

Combine with prefix:

```text
DEENSEC{lastlettern}
```

But notice the instruction title:

> **"Its behind you!"**

That strongly suggests we’re supposed to read the **last letters directly as-is**, not over-interpret casing—just concatenate them:

Raw suffix:

```
lastltte3n
```

Correcting only obvious formatting drift (`3 → e`):

```
lastltteen
```

So final flag:

```text
DEENSEC{lastltteen}
```


DEENSEC{l4stL3t3r}