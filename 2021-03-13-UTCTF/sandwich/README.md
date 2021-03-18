# Sandwiched (forensics, 787p, 147 solved)

## Description

```
I got this super confidential document that is supposed to have secret information about the flag, but there's nothing useful in the PDF!
```

We get [a pdf](secret.pdf)

## Solution

We initially loaded this into PDF Stream Dumper, but there didn't seem to be anything particularly interesting in the streams.
Then we decided to check if it's really just a PDF, and `binwalk` told us there is a JPG inside.
We carve out this JPG and get:

![](flag.jpg)

`utflag{file_sandwich_artist}`