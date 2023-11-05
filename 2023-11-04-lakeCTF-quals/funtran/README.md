# Funtran (re)

## Introduction

In the challenge we get a [binary](funtran) and also some [fortran library code](arrayops.f90).
The binary reads a single floating point number from us and checks if it's correct or not.

## Analysis

The code looks really complex, so we focused only on the "essentials".
We can easily spot a string:

```
"yay u got it !! :33 your flag is EPFL{replace_this_by_the_ten_first_decimal_places_o f_your_input}"
```

which tells us we need to find a floating point value with lots of decimal digits, but we also need only 10 of them.

Right before that check we have:

```c
  uVar6 = __integrate_MOD_trapz(&puStack_238,&x.2);
  if (9.999999999999999e-12 <= (double)(uVar6 & 0x7fffffffffffffff)) {
```

so at the very end of the calculations there is some numerical integration happening and finally the result is checked to be very close to 0.

## Solution

The code looked way too complex to analyze statically, so intead we attached a debugger at the last check, and inspected how our inputs compare with the expected value.
We can break at `0x004022cc`, then `print $xmm0` and check contents of `v2_double`.

By sending a handful of inputs we noticed that the behaviour is very interesting - there is a clear "minimum" of that function.
For example:

```
8.2 -> v2_double = (0.10662386291810402, 0)
8.3 -> v2_double = (0.0066238629181169673, 0)
8.4 -> v2_double = (0.093376137081901817, 0)
```

going below 8.2 and above 8.4 makes the value grow very fast.

We can see similar pattern when drilling down one more decimal place and inspecting results for values between 8.20 and 8.40, we again hit a minimum at exactly `8.30`, and going one level deeper at `8.306`.

So it's clear we can simply brute-force this decimal-by-decimal, feeding the binary the numbers and looking for the minimum.
We repeat this process a couple of times until we reach `8.3066238629` which is enough to submit as a flag `EPFL{3066238629}`.
Interestingly this is actually not enough to get the win message, for that we need to go one step deeper with `8.30662386291` or `8.30662386292`.
