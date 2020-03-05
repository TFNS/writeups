# Drawings on the walls (forensics, 100p, 113 solved)

A classic guessy forensics challenge.
We get a ~2GB memdump of windows machine and we're supposed to find flags there.

You can try to use volatility but it's not really useful here.
It boils down to strings+grep skills.

Looking for `Aero{` in the memdump shows some fake flags, but when we switch to looking for unicode strings we hit unicode string `A.e.r.o.{.g.0.0.d.j.0.b._.y`.
That's not a whole flag, but now we can look around for `g00d` and we find `g00dj0b_y..0u_f1n4..11y_g07_7h3_wh0l3_fl4g`

We can merge this and submit `Aero{g00dj0b_y0u_f1n411y_g07_7h3_wh0l3_fl4g}`

In the meantime we found also an interesting string `Here is AEORCTF keepass master key: FUCK_U_BEATCH_SUCK_KIRPITCH` but we were unable to locate the keepass db.
It was not in the memdump.
It turns out you had to guess that there is a pastebin link there...
