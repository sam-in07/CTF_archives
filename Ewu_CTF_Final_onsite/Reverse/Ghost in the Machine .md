This image came off the main controller of a unit that kept operating long after it was supposedly shut down. The vendor built the firmware to resist anyone taking it apart, load it into your tools and the routine at its heart reads like deliberate static. Buried somewhere inside is a factory service credential that was never meant to ship on production hardware. Recover it, and you'll have your first answer about what this machine really was.


Soln : 

 The binary dynamically decrypts and executes shellcode at runtime. The execution flow inside  FUN_00101170  proceeds as follows:

  1. Reads a 38-character ( 0x26 ) string input from the user.
  2. Allocates memory via  mmap , copies  0x5a  (90) bytes from  DAT_001020a0 , XOR-decrypts them with key  0x7c , and marks the page
  executable via  mprotect .
  3. Calls the decrypted routine, passing the input string and an encrypted verification table at  DAT_00102060 .

#### Shellcode Algorithm

  The decrypted function checks each character i (from 0 to 37) against the target array:

    target [i] ≡ Big (big ((i + 0x5a) oplus ROL₈ (input [i],3) big) + 7 × i Big) pmod 256
    
  #### Reversing the Algorithm

  To recover each character of the flag:

  1. Calculate val = (i + 0x5a) oplus ((target [i] - 7 × i) pmod 256).
  2. Rotate right by 3 bits: input [i] = ROR₈ (val,3).
  ──────
  ### Recovered Credential / Flag

   ROBOFEST{s3lf_d3crypt1ng_c0d3_runt1m3} 