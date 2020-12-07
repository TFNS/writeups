# Yopass Go (re, 50p, 153 solved)

## Description

```
The password is so clear that it is the flag itself.

Flag format: CTF{sha256}
```

In the task we get a [binary](yopass).

## Solution

Not sure what the binary does at all, first sanity check with `strings yopass | grep ctf{` gives:

`ctf{0962393ce380c3cf696c6c59a085cde0f7edd1382f2e9090220abdf9a6396c88}`
