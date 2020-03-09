# Locked KitKat (forensics, 100p, ? solved)

Pretty nice and simple forensics challenge.
We get image of Android device and we're supposed to extract the pattern lock.

If we read a bit about it it turns out the [pattern](gesture.key) is stored at `/system/gesture.key` and it's just SHA hash of the pattern.

We just grabbed some random cracked for that, something like https://gist.github.com/ducphanduyagentp/9968516 and after few seconds we get back the solution:

```
[:D] The pattern has been FOUND!!! => 321564

[+] Gesture:

  -----  -----  -----
  |   |  | 3 |  | 2 |  
  -----  -----  -----
  -----  -----  -----
  | 1 |  | 6 |  | 4 |  
  -----  -----  -----
  -----  -----  -----
  | 5 |  |   |  |   |  
  -----  -----  -----
```

Once we input this we get: `zer0pts{n0th1ng_1s_m0r3_pr4ct1c4l_th4n_brut3_f0rc1ng}`
