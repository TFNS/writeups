# Hellish RE (re, 50p, 134 solved)

In the task we get an [archive](hellishreverse.tar.gz).
This is important here, because the python flag checker inside the archive is impossible to reverse.
The troll/trick here is that if we unpack this in two steps, first just gzip and then tar, we notice that the stored tar has a very interesting name: `vos_rebyc10_hellishreverse_verify_with_cybrics{ok_t4ht_wA5_qu1T3_4n_un3Xpec7eD_w4Y}.tar`

We submit `cybrics{ok_t4ht_wA5_qu1T3_4n_un3Xpec7eD_w4Y}` to get the points.
