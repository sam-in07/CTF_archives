 Analyzing the Echo Service
  ### Vulnerability Analysis & Exploit Strategy for Echo Service v2

  The provided Ghidra disassembly reveals a classic Format String Vulnerability combined with a GOT (Global Offset Table) Overwrite.
  ──────
  ### Key Findings from Assembly Analysis

  1. Format String Vulnerability ( main  @  0x401230 ):
      • User input is read into stack buffer  local_98  ( RBP - 0x90 ) via  fgets  (reading up to  0x80  bytes).
      • At address  0x401326 , the binary executes  printf(local_98)  directly without passing a specifier (i.e., missing  printf("%s",
      buf) ).
  2. Target Backdoor Function ( win  @  0x401216 ):
      • Located at  0x401216 , the  win  function prepares  /bin/cat flag.txt  and calls  system() .
  3. Exploitation Vector & Control Flow Hijack:
      • Right after  printf  finishes at  0x401326 , the binary immediately invokes  putchar('\n')  at  0x401330 .
      • Since the binary is non-PIE and has Partial RELRO,  putchar@GOT  ( 0x404000 ) is located at a fixed writable memory address.
      • By using format string specifiers ( %n  /  %hn  /  %hhn ), we can write  0x401216  ( win ) into  0x404000  ( putchar@GOT ). When
      putchar  is called next, control flow jumps directly to  win() .
      • On x86_64, the input buffer on the stack starts at format argument offset  6  ( %6$p ).

  ──────
  ### Exploit Script ( solve.py )

  You can utilize  pwntools  to automate generating the format string payload:

    from pwn import *
    
    # Load binary context
    context.binary = elf = ELF('./echo_service', checksec=False)
    
    def main():
        p = process('./echo_service')
        
        # Target: overwrite putchar@GOT (0x404000) with win (0x401216)
        # Stack offset for local_98 buffer is 6
        payload = fmtstr_payload(6, {elf.got['putchar']: elf.sym['win']})
        
        p.sendlineafter(b'> ', payload)
        p.interactive()
    
    if __name__ == '__main__':
        main()
    ──────
  ### Summary of Work

  • Conducted binary analysis of the assembly listing provided.
  • Identified format string flaw at  printf  ( 0x401326 ) and target  win  function at  0x401216 .
  • Formulated  putchar@GOT  ( 0x404000 ) overwrite strategy to hijack program control flow.
  • Cross-referenced workspace files in Echo Service v2.md and solve.py.

────────────────────────────────────────────────────────────


▸
  ──────
 

  │ "We analyzed the disassembly of the echo service binary and found a Format String Vulnerability. Because the binary has Partial
  RELRO
  │ and No PIE, we used the format string flaw to overwrite the Global Offset Table (GOT) entry of  putchar  with the address of the
  │ backdoor  win  function. As soon as  printf  completes, the binary calls  putchar , which immediately redirects control flow to 
  │ win()  and prints the flag."
  ──────
  ### 📋 Detailed Point-by-Point Breakdown (If the judge asks follow-up questions)

  #### 1. What is the vulnerability? (Format String Flaw)

  • Assembly Location: Address  0x401326  inside  main .
  • Explanation: The binary reads user input into a stack buffer using  fgets  and then calls  printf(buf)  directly without a format
  specifier like  %s .
  • Impact: Passing user input directly into  printf  allows us to inject format specifiers like  %p  to leak memory or  %n  to write
  arbitrary values into memory.

  #### 2. What binary protections were enabled/disabled?

  • No PIE (Position Independent Executable): The code and function addresses are fixed in memory. The  win  function is permanently at
  address  0x401216 .
  • Partial RELRO (Relocation Read-Only): The  .got.plt  section (Global Offset Table) remains writable at fixed addresses.  putchar@GOT
  is located at  0x404000 .

  #### 3. How does the target  win  function work?

  • Inside  win  (address  0x401216 ), the binary executes  system("/bin/cat flag.txt") . Our goal is simply to redirect program
  execution to this address.

  #### 4. How did you hijack control flow?

  • Right after the vulnerable  printf  call at  0x401326 , the binary immediately calls  putchar('\n')  at  0x401330 .
  • We constructed a format string payload ( fmtstr_payload  in  pwntools ) targeting offset  6  (the starting offset of standard stack
  arguments on x86_64 Linux ABI).
  • Our payload writes the value  0x401216  ( win ) into memory address  0x404000  ( putchar@GOT ).
  • When  putchar  is invoked on line  0x401330 , instead of jumping into libc's  putchar , it jumps straight to  win() , giving us the
  flag!
  ──────
  ### 💡 Quick Answers to Likely Judge Questions

  • Judge: "Why did you overwrite  putchar  specifically and not another function?"
      • Answer: "Because  putchar  is called immediately after  printf  in the loop ( 0x401330 ). Overwriting its GOT entry gives us
      instant control flow hijacking right after our format string payload executes."
  • Judge: "Why is the format string parameter index 6?"
      • Answer: "On 64-bit Linux System V ABI, the first 6 integer/pointer arguments to a function are passed in registers ( RDI ,  RSI ,
      RDX ,  RCX ,  R8 ,  R9 ), and subsequent arguments come from the stack. The input buffer on the stack aligns with the 6th format
      argument index ( %6$p )."

  ──────
  ### Summary of Work

  • Created a judge presentation guide breaking down the vulnerability, binary protections, and control flow hijacking vector.
  • Provided a concise spoken respons  and prepared answers for expected judge follow-up technical questions.



  ============================







    The provided Ghidra disassembly reveals a classic Format String Vulnerability combined with a GOT (Global Offset Table) Overwrite.
  ──────
  ### Key Findings from Assembly Analysis
  
  1. Format String Vulnerability ( main  @  0x401230 ):
      • User input is read into stack buffer  local_98  ( RBP - 0x90 ) via  fgets  (reading up to  0x80  bytes).
      • At address  0x401326 , the binary executes  printf(local_98)  directly without passing a specifier (i.e., missing  printf("%s",
      buf) ).
  2. Target Backdoor Function ( win  @  0x401216 ):
      • Located at  0x401216 , the  win  function prepares  /bin/cat flag.txt  and calls  system() .
  3. Exploitation Vector & Control Flow Hijack:
      • Right after  printf  finishes at  0x401326 , the binary immediately invokes  putchar('\n')  at  0x401330 .
      • Since the binary is non-PIE and has Partial RELRO,  putchar@GOT  ( 0x404000 ) is located at a fixed writable memory address.
      • By using format string specifiers ( %n  /  %hn  /  %hhn ), we can write  0x401216  ( win ) into  0x404000  ( putchar@GOT ). When
      putchar  is called next, control flow jumps directly to  win() .
      • On x86_64, the input buffer on the stack starts at format argument offset  6  ( %6$p ).

  ──────
  ### Exploit Script ( solve.py )

  You can utilize  pwntools  to automate generating the format string payload:

    from pwn import *
    
    # Load binary context
    context.binary = elf = ELF('./echo_service', checksec=False)
    
    def main():
        p = process('./echo_service')
        
        # Target: overwrite putchar@GOT (0x404000) with win (0x401216)
        # Stack offset for local_98 buffer is 6
        payload = fmtstr_payload(6, {elf.got['putchar']: elf.sym['win']})
        
        p.sendlineafter(b'> ', payload)
        p.interactive()
    
    if __name__ == '__main__':
        main()
    ──────
  ### Summary of Work

  • Conducted binary analysis of the assembly listing provided.
  • Identified format string flaw at  printf  ( 0x401326 ) and target  win  function at  0x401216 .
  • Formulated  putchar@GOT  ( 0x404000 ) overwrite strategy to hijack program control flow.
  • Cross-referenced workspace files in Echo Service v2.md and solve.py.


[+] Starting local process './echo_service': pid 145717
[*] Switching to interactive mode


