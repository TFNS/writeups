# 7-11 (stegano, 100p, 138 solved)

## Description

In the task we get a [7 zip archive](challenge.7z) and there are 2 flags hidden there.
For the second part see `7-12` writeup.

## Archive analysis

### ZIP content

We start off by simply checking what's in the archive, and there is one file `password.txt` with:

```
        _                                 _   _               __ _             
   __ _(_)_   _____     _ __ ___   ___   | |_| |__   ___     / _| | __ _  __ _ 
  / _` | \ \ / / _ \   | '_ ` _ \ / _ \  | __| '_ \ / _ \   | |_| |/ _` |/ _` |
 | (_| | |\ V /  __/   | | | | | |  __/  | |_| | | |  __/   |  _| | (_| | (_| |
  \__, |_| \_/ \___|___|_| |_| |_|\___|___\__|_| |_|\___|___|_| |_|\__,_|\__, |
  |___/           |_____|            |_____|           |_____|           |___/ 

```

So we have some password `give_me_the_flag`, now we just need to use it somewhere.
It's interesting that this archive is so big (151KB) and has only a small file inside...

If we peek inside via hexeditor or run `binwalk` we can see that there is another 7zip archive glued to the first one.

### Second archive

We can cut-out the second [archive](challenge2.7z) and unpack it using the provided password.
From this we get the first flag: `tstlss{next_header_offset_is_a_nice_feature}` which is also a hint for second stage, and also input files for the second stage.
