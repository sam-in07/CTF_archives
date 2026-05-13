On June 29, 2019, at 07:29 AM UTC, a memory image was captured from a Windows 7 workstation registered to a user known as SlimShady , a person of interest in an active digital investigation. The capture was performed using DumpIt.exe, a legitimate forensic tool, moments before the machine was remotely isolated. The image preserves a snapshot of everything that was running at the time: every process, every command, every byte still loaded in RAM. Initial triage identified several anomalies across multiple processes. Evidence of obfuscation, data staging, and deliberate fragmentation suggests the machine was actively being used as part of a larger operation at the time of capture. Your task is to analyze the memory image and reconstruct what happened.

Note: For all Mem series challenges, there will be the same scenario and attachment file.

Attachment Link: [File](https://drive.google.com/file/d/1NQHwesxegmbpA0_kIV2NYeX7IEqKRhhd/view?usp=sharing)

Among the running processes, analysts noticed StikyNot.exe — Windows' sticky notes application. Nothing unusual about that. Except StikyNot.exe doesn't take command-line arguments. This one did.

Examine the command line of StikyNot. What argument was passed to it?

Flag : 

point : 100

Status : unSolved