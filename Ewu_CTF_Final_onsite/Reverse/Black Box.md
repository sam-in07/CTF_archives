The event recorder, the module every unit in the fleet carries to log what it did and why. Pulling it apart is almost too easy; the contents lay themselves out in front of you on the first try. But the one thing you actually came for isn't written down anywhere in plain form. It was put away deliberately, behind a step you have to walk through yourself before it means anything. Reading the records is not the same as reading the secret.

soln : 

Solver : [sam_in_Ironside](https://github.com/sam-in07)

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




## Challenge Overview

The Java program verifies whether the user enters the correct flag. Instead of storing the flag directly, it stores an array of transformed byte values and checks each character using bitwise operations.

Our goal is to reverse the transformation to recover the original flag.

---

## Step 1: Analyze the Verification Code

The program stores the following integer array:

```java
int[] var1 = {
208, 57, 86, 63, 116, 109, 210, 235, 145, 24,
237, 254, 239, 181, 67, 154, 241, 202, 79, 212,
117, 206, 162, 122, 195, 64, 39, 54, 221, 214,
3, 248, 249, 153, 127, 6, 255, 198, 27, 130
};
```

The program expects the user to enter exactly **40 characters**.

For each character, it performs the following check:

```java
int var6 = var1[i] ^ ((66 + i) & 255);

if (r8(var6, 3) != input.charAt(i)) {
    return false;
}
```

The rotation function is:

```java
static int r8(int value, int shift) {
    shift &= 7;
    return (value >>> shift | value << (8 - shift)) & 255;
}
```

This performs an **8-bit right rotation by 3 bits**.

---

## Step 2: Understand the Transformation

For every position `i`, the program:

1. Takes the stored byte `var1[i]`.
2. XORs it with `(66 + i)`.
3. Rotates the result right by 3 bits.
4. Compares the final value with the user's input character.

Mathematically:

```
input[i] = RotateRight8(var1[i] ^ (66 + i), 3)
```

Since the program directly computes the expected character, we can simply apply the same transformation to every value in the array to recover the original input.

---

## Step 3: Recover the Flag

Running the transformation on each element of `var1` produces the following string:

```
ROBOFEST{j4v4_byt3c0d3_d3comp1l3s_cl34n}
```

---

## Final Flag

```text
ROBOFEST{j4v4_byt3c0d3_d3comp1l3s_cl34n}
```

---

## Conclusion

This challenge relied on understanding Java operator precedence and simple bitwise operations.

The important observations were:

* `+` is evaluated before `&`, and `&` is evaluated before `^`.
* The program XORs each stored byte with `(66 + index)`.
* It then performs an 8-bit right rotation by 3 bits.
* Executing the same transformation on every array element directly reconstructs the expected input.

Once these operations were understood, recovering the flag was straightforward.

