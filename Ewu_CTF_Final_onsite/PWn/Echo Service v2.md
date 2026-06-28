Our new echo service repeats whatever you type. We even let you format it nicely. What could go wrong?


Soln :   

  ### Key Findings from Assembly Analysis
  0x0000000000401326 <+246>:   call   0x4010e0 <printf@plt>
  the binary executes  printf(local_98)  directly without passing a specifier

    0x0000000000401216 <+0>:     endbr64
     Located at  0x401216 , the  win  function prepares  /bin/cat flag.txt  and calls  system() .

     inside  win  (address  0x401216 ), the binary executes  system("/bin/cat flag.txt")

  the value  0x401216  ( win ) into memory address  0x404000  ( putchar@GOT ).

  putchar  is invoked on line  0x401330 , instead of jumping into libc's  putchar , it jumps straight to  win() , giving us the
  flag!


ROBOFEST{f0rm4t_str1ng_t0_w1n_2026}
