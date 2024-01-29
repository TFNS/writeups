# The truth of Plain - Real World CTF 6th (crypto, 63 solved, 87p)
## Introduction
The truth of Plain is a cryptography task.

An archive containing a pcap and a ZIP file is given.

## ZIP file
The ZIP file is protected by a password. The content of the ZIP is encrypted
with the ZipCrypto algorithm.

This file contains two entries:
- `key`, a compressed file (probably some text)
- `Document.zip`, an uncompressed file (probably an other ZIP archive)

```
Archive: Secret.zip
Index Encryption Compression CRC32    Uncompressed  Packed size Name
----- ---------- ----------- -------- ------------ ------------ ----------------
    0 ZipCrypto  Deflate     89164568         2008         1044 key
    1 ZipCrypto  Store       1f9a24ff          415          427 Document.zip
```


## Recovering plaintext
By making the following assumptions:
- `Document.zip` is a valid ZIP file
- It has been created on the same system as `Secret.zip`

it is possible to infer some bytes of `Document.zip`


The [Wikipedia article] for the ZIP file format describes the following
structure
| Offset | Bytes | Description
|--------|-------|-------------------------------------------------------------
| 0      |  4 	 | End of central directory signature = 0x06054b50
| 4      |  2 	 | Number of this disk (or 0xffff for ZIP64)
| 6      |  2 	 | Disk where central directory starts (or 0xffff for ZIP64)
| 8      |  2 	 | Number of central directory records on this disk (or 0xffff for ZIP64)
| 10     |  2 	 | Total number of central directory records (or 0xffff for ZIP64)
| 12     |  4 	 | Size of central directory (bytes) (or 0xffffffff for ZIP64)
| 16     |  4 	 | Offset of start of central directory, relative to start of archive (or 0xffffffff for ZIP64)
| 20     |  2 	 | Comment length (n)
| 22     |  n 	 | Comment

[Wikipedia article]: https://en.wikipedia.org/wiki/ZIP_(file_format)?useskin=vector#End_of_central_directory_record_(EOCD)

Most of these bytes are known, or can be guessed because the file is small.
For example, it is very likely that the number of disk is 0.

These assumptions are:
```
50 4B 05 06  magic
00 00        number of this disk
00 00        disk of central dir
?? 00        number of central dir records
?? ?? 00 00  size of central dir
?? ?? 00 00  offset of central dir
00 00        comment length
```

## Cracking the ZIP file
It is possible to use `bkcrack` to perform a KPA on `Secret.zip`:
```sh
bkcrack -C ./Secret.zip -c 'Document.zip' \
	-x 0                        '504B0304' \
	-x $((415 - 0x16 + 0))      '504B0506' \
	-x $((415 - 0x16 + 4))      '0000' \
	-x $((415 - 0x16 + 6))      '0000' \
	-x $((415 - 0x16 + 10 + 1)) '00' \
	-x $((415 - 0x16 + 12 + 2)) '0000' \
	-x $((415 - 0x16 + 16 + 2)) '0000' \
	-x $((415 - 0x16 + 20))     '0000'
```

This yields the ZIP master key: `368b7c25 d8b6163f d5c85e0b`.

This master key can be used to change the password of the ZIP file.
```sh
# Change the password to "TFNS"
bkcrack -C ./Secret.zip -k 368b7c25 d8b6163f d5c85e0b -U new.zip TFNS

# Extract the new zip file
7z x -pTFNS new.zip
```

The `Document.zip` file contains the flag, but it is encrypted too.
The password for this archive is somewhere in the `key` file.

> Remember, the password is 7dd5c046fdb876f6351f4e04e8b43a20

**Flag**: `rwctf{58efb2e01a57e38359398ccb5ee7281707fa91a78e1704755e61e62a7e054445}`
