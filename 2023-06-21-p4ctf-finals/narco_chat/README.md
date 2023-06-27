# Narco chat (misc, 8 solves, 328p)

## Introduction

The task start as a RE, but then it turns more into some blackbox web task.
We get a binary to work with, however this binary is actually pyinstaller generated.

## Task analysis

We can use some extractor like https://github.com/extremecoders-re/pyinstxtractor or simply binwalk the binary to extract the relevant [.pyc](client.pyc) file.

It seems a pretty recent pyc version from latest python, and we're unable to run any uncomplyle/decompyle on it, so we're left with looking at `dis.dis` and running the code.

We can import `client` we recovered and introspect it:

```
>>> dir(client)
['BANNER', 'HTTPConnection', '__builtins__', '__cached__', '__doc__', '__file__', '__loader__', '__name__', '__package__', '__spec__', 'b64encode', 'encrypt_data', 'get_messages', 'get_messages_action', 'main_loop', 'print_lines', 're', 'register', 'register_action', 'send_message', 'send_message_action', 'time']
```

`main_loop` shows a menu with 3 options -> register, get messages, send message.
We can introspect the functions further to find the API endpoint it's talking to, however it seems all payloads are encrypted using some custom function and then encoded as base64.

Registering new user gives us some random ID which looks like a hash, and this ID we can later use to read messages.
Trying to re-register user gives an error.
Encryption function has some regex check on input, however we can easily just rig `re.match` to always be `True` if we want to bypass it and use any payloads we want.

We spent some time looking into `dis.dis()` or each function, but it didn't seem to be particularly interesting.

## Solution

We spent a lot of time trying to guess what can be an issue here.
There are lots of potential avenues to look into:

1. Maybe we can register the same user twice by making "equivalent" base64 using unused bits?
2. Maybe we can register the same user twice by encrypting some `\x00` or `\n` or something similar?
3. Maybe we can somehow predict the user IDs by figuring out how the hash is computed (eg. maybe some md5(username+secret))

The actual solution we found purely by accident. 
While sending random requests we at some point got back "DB error" message.
This pointed us to potential SQLi when trying to read messages.
We could do a classic `'or'1'='1` trick to read all messages, not only those belonging to our user and getting the flag: `p4{Was_this_a_crypto?a_web?a_re?who_the_hell_knows}`
