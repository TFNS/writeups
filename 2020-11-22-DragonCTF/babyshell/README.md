# babyshell - Dragon CTF 2020 (Miscellaneous, 242p, 38 solved)

## Introduction
babyshell is a miscellaneous task.

An archive containing a kernel, an initrd and a script to run a virtual machine
is given.

## Reverse engineering
When the virtual machine boots, the kernel will spawn `/init` as the first
process. This script starts the `/bin/server` binary.

This binary is not stripped and relatively small. Understanding its purpose is
straightforward.

The binary opens an SSL server on port 4433 and waits for a connection. When a
new connection is accepted, the server sends a random number generated with
`rand` (but without calls to `srand`).

If the client answers the same number, the server prints the flag.

## Connection
The virtual machine has very few utilities. It is possible to open a connection
with `busybox nc`, but `nc` is not able to make a TLS handshake.

The easiest solution is to use nc and offload the TLS handshake outside of the
virtual machine (similar to how `STARTTLS` works in some protocols.)

Sending binary data over the wire is tricky because the terminal will alter the
input (e.g. intercept `\x03` and send a `SIGINT` to the process) and the output
(e.g. automatically convert `\n` to `\r\n`).

This last problem can be solved with `stty raw -echo`. This disables all kind of
options on the tty to prevent input and output mangling (`raw`) and prevents the
terminal from outputing what characters are sent, just like when `sudo` asks for
a password (`-echo`).

**Flag**: `DrgnS{Shellcoding_and_shellscripting_whats_not_to_like}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php
const HOST = "babyshell.hackable.software";
//const HOST = "127.0.0.1";
const PORT = 1337;

function read_n($fp, $n)
{
	$buffer = "";

	while(strlen($buffer) < $n)
		$buffer .= fread($fp, $n - strlen($buffer));

	return $buffer;
}

$fp = fsockopen(HOST, PORT);
if(HOST !== "127.0.0.1") {
	$pow = fgets($fp);
	echo $pow;

	$result = fgets(STDIN);
	fwrite($fp, $result);
}

$i = 0;
do {
	$line = fgets($fp);
	printf("%d: %s", $i++, $line);
	if($line === false)
		exit;
} while(false === strpos($line, "/etc/motd"));

fgets($fp);
read_n($fp, strlen("(none):~$ "));

/* Turn the tty in a raw tube */
fwrite($fp, "stty raw -echo\n");
printf("[%s]\n", fgets($fp));

printf("[+] Waiting for server to start\n");
sleep(5);

fwrite($fp, "exec busybox nc 0 4433\n");
printf("[%s]\n", fgets($fp));

/* Enable crypto */
stream_context_set_option($fp, "ssl", "verify_peer", false);
stream_context_set_option($fp, "ssl", "verify_peer_name", false);
stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_ANY_CLIENT);

/* Answer the challenge */
$n = fgets($fp);
var_dump($n);
fwrite($fp, $n);

/* Read the output */
while($line = fgets($fp))
	echo $line;
```
