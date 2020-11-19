# The Last Bitcon - Balsn CTF 2020 (misc, 238p, 50 solved)
## Introduction

This challenge consists of a single Python script.
The script is a proof-of-work. It generates a prefix and asks for a string that,
once hashed in `sha256`, starts with 200 bits set to 0.

## Fuzzing
The script does not look vulnerable, but it has to be.
A bash one-liner was used to send random bytes (from `/dev/urandom`) to see how
the remote service behaves.
```shell
% (head -c $((0x80)) /dev/urandom; cat) | nc the-last-bitcoin.balsnctf.com 7123

sha256(GJbkiuJabiZpRkMA + ???) == 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000(200)...

??? =
There you go:
BALSN{Taiwan_can_help_solve_sha256}
```

**Flag**: `BALSN{Taiwan_can_help_solve_sha256}`
