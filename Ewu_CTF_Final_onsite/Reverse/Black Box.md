The event recorder, the module every unit in the fleet carries to log what it did and why. Pulling it apart is almost too easy; the contents lay themselves out in front of you on the first try. But the one thing you actually came for isn't written down anywhere in plain form. It was put away deliberately, behind a step you have to walk through yourself before it means anything. Reading the records is not the same as reading the secret.

soln : 


```java

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Check {
   static int r8(int var0, int var1) {
      var1 &= 7;
      return (var0 >>> var1 | var0 << 8 - var1) & 255;
   }

   public static void main(String[] var0) throws Exception {
      int[] var1 = new int[]{208, 57, 86, 63, 116, 109, 210, 235, 145, 24, 237, 254, 239, 181, 67, 154, 241, 202, 79, 212, 117, 206, 162, 122, 195, 64, 39, 54, 221, 214, 3, 248, 249, 153, 127, 6, 255, 198, 27, 130};
      BufferedReader var2 = new BufferedReader(new InputStreamReader(System.in));
      System.out.print("Enter flag: ");
      String var3 = var2.readLine().trim();
      if (var3.length() != var1.length) {
         System.out.println("Nope.");
      } else {
         boolean var4 = true;

         for(int var5 = 0; var5 < var1.length; ++var5) {
            int var6 = var1[var5] ^ 66 + var5 & 255;
            if (r8(var6, 3) != (var3.charAt(var5) & 255)) {
               var4 = false;
            }
         }

         System.out.println(var4 ? "Correct! Submit what you typed." : "Nope.");
      }
   }
}
```



  The Java code in  Check.java  validates a user-provided flag of length 40 against a target byte array  var1 .

  #### Verification Algorithm

  For each index  var5  from 0 to 39:

  1.  var6  is computed using bitwise operations and arithmetic precedence:
   int var6 = var1[var5] ^ 66 + var5 & 255; 
  (Note: In Java, arithmetic  +  evaluates first, followed by bitwise AND  & , and finally bitwise XOR  ^ ).
  
  2. The expected character code is obtained by performing an 8-bit right rotation on  var6  by 3 bits:
   r8(var6, 3)  which computes  (var6 >>> 3 | var6 << 5) & 255 .

  #### Key Recovery

  By directly executing the forward transformation on each element of  var1 , we reconstruct the original input string character by
  character.
  ──────
  ### Recovered Secret / Flag


 ROBOFEST{j4v4_byt3c0d3_d3comp1l3s_cl34n}  