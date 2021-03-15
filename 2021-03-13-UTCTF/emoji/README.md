# Emoji encryption (misc, 100p, 379 solved)

## Description

```
I came up with this rad new encryption. Bet no one can break it

☂️🦃🔥🦁🍎🎸{🐘🥭🧅🤹🧊☀️_💣🐘_🌋🐘🌈☀️🍎🦃🧊🦁🐘}
```


## Task analysis

Flag format is preserved, so we can expect each emoji to encode a single letter.
We know that format is `utflag{}`.


## Solution

First letter of the flag should be `u` and emoji is `umbrella`, second letter should be `t` and emoji is `turkey`...

`utflag{emojis_be_versatile}`
