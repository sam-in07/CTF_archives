Sophisticated attackers don't store payloads in one place. They fragment them splitting data across unrelated memory regions so that no single artifact reveals the full picture. A partial scan of conhost.exe found three distinct blobs of encoded data, each too short to be meaningful on its own. They are not random. They are pieces of a whole. Each fragment is labeled, each is encoded the same way. The challenge is finding them, decoding them, and assembling them in the correct order.

**Three encoded fragments are hidden in conhost.exe memory, each preceded by a labeled marker (CTXBLK_A, CTXBLK_B, CTXBLK_C). Decode each and assemble the flag in order.**

Flag : 

point : 300

Status : unolved