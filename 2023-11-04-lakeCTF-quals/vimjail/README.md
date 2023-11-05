# VimJail (misc)

## Introduction

In the challenge we can connect to a remote host via ssh and we get dropped immediately into `vim` running in `insert mode` with lots of custom keymappings.

## Analysis

We get access to [config](chall_vimrc1) which is applied for both tasks, although part 2 of the challenge is supposed to have one additional line, however the solutions are almost exactly the same.

The main difficulty of the task comes from the fact that we simply can't exit `insert mode` - no standard ways like `ESC` or a bunch of different control sequences are disabled.
On top of that almost all lowercase characters are remapped to `_` so even if we could enter `normal mode` we would have hard time typing any sensible commands.

## Solution

Our approach was to leverage special modes you can enter, specifically `ctrl+r` which takes us into `register mode`.
One especially interesting feature of this mode allowes to evaluate expressions when we do `c-r =`.
After `=` we can type expression, including builtin vim functions, and they will get evaluated.
This means we could do `c-r =system("cat flag")`, if we could type such command.

In part2 of the challenge `c-r` was also remapped and could not be used directly, however it was possible to first enter `completion mode` with `ctrl+x` and from that proceed again to `c-r =` same as before.

Now that we can execute commands we need a way to actually type some sensible command.
We can write uppercase characters, but there are no useful uppercase functions for us to use.
We could use vim autocomplete features to help us typing, but it seems they first require we type some data to be later used for autocompletion.
It turns out while we're in `c-r =` we can do `c-d` to show list of available functions and we can also do `c-a` to (for whatever reason) dump all all of that into a string.
While of course it will not execute because of errors, now we managed to feed autocomplete with all function names!

Now we can again do (`c-x`) `c-r =` then `c-f` to see history of executed commands and we can finally do `c-p` to get autocompletion of all available function names.
Now we can simply scroll down to look for `system` and another `c-p` to scroll for `tolower` and construct `system(tolower("CAT FLAG"))` call to get the flags.

`EPFL{i_could_have_guessed_it}`

`EPFL{vim_worse_than_macs_eh}`
