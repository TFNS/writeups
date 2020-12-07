# spy agents (forensics, 293p, 30 solved)

## Description

```
A malicious application was sent to our target, who managed to have it before we confiscated the PC. Can you manage to obtain the secret message?

Flag format: ctf{sha256(location name from coordinates in lowercase)}
```

In the task we get a 1GB image file (not attached)

## Task analysis

First problem was `what even is this file`.
It seemed like MBR file, but we could not mount or unpack it.
Binwalk was also not very helpful, because from quick glance in hexeditor it was clear that while there are some files, they are not in `continuous` blocks.

After some time we found that it might be `fmem` dump file.

### Volatility to the rescue

Since its's a memdump, we tried to do something using volatility and it worked.

```
volatility_2.6.exe -f spyagency3.img --profile Win7SP1x64 pslist
Volatility Foundation Volatility Framework 2.6
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xfffffa8000c9d040 System                    4      0     82      493 ------      0 2020-12-04 23:43:09 UTC+0000
0xfffffa8001d61b30 smss.exe                248      4      2       29 ------      0 2020-12-04 23:43:09 UTC+0000
0xfffffa8001d34060 csrss.exe               320    312      8      375      0      0 2020-12-04 23:43:12 UTC+0000
0xfffffa8002227060 wininit.exe             368    312      3       74      0      0 2020-12-04 23:43:12 UTC+0000
0xfffffa800238d060 csrss.exe               380    360      7      155      1      0 2020-12-04 23:43:12 UTC+0000
0xfffffa80025ae7d0 winlogon.exe            420    360      3      111      1      0 2020-12-04 23:43:12 UTC+0000
0xfffffa800244c910 services.exe            464    368     10      190      0      0 2020-12-04 23:43:12 UTC+0000
0xfffffa8002652b30 lsass.exe               476    368      7      543      0      0 2020-12-04 23:43:12 UTC+0000
0xfffffa8002663b30 lsm.exe                 484    368     10      140      0      0 2020-12-04 23:43:12 UTC+0000
0xfffffa800272b810 svchost.exe             588    464     10      347      0      0 2020-12-04 23:43:12 UTC+0000
0xfffffa8002494890 svchost.exe             652    464      9      257      0      0 2020-12-04 23:43:13 UTC+0000
0xfffffa800278fb30 svchost.exe             704    464     21      526      0      0 2020-12-04 23:43:13 UTC+0000
0xfffffa80027d1b30 svchost.exe             812    464     23      452      0      0 2020-12-04 23:43:13 UTC+0000
0xfffffa8002808060 svchost.exe             860    464     30      926      0      0 2020-12-04 23:43:13 UTC+0000
0xfffffa800283bb30 svchost.exe             972    464     16      436      0      0 2020-12-04 23:43:13 UTC+0000
0xfffffa8002679800 svchost.exe             280    464     15      357      0      0 2020-12-04 23:43:13 UTC+0000
0xfffffa800286eb30 spoolsv.exe            1016    464     12      274      0      0 2020-12-04 23:43:13 UTC+0000
0xfffffa80029bc890 svchost.exe            1064    464     18      296      0      0 2020-12-04 23:43:13 UTC+0000
0xfffffa8002a1f8a0 taskhost.exe           1136    464      8      144      1      0 2020-12-04 23:43:13 UTC+0000
0xfffffa8002a72b30 sppsvc.exe             1584    464      4      143      0      0 2020-12-04 23:43:14 UTC+0000
0xfffffa8002c58b30 GoogleCrashHan         1932   1900      5       97      0      1 2020-12-04 23:43:15 UTC+0000
0xfffffa8002c5db30 GoogleCrashHan         1940   1900      5       90      0      0 2020-12-04 23:43:15 UTC+0000
0xfffffa8002a79360 dwm.exe                1996    812      3       69      1      0 2020-12-04 23:45:14 UTC+0000
0xfffffa8002541530 explorer.exe            648   1896     35      892      1      0 2020-12-04 23:45:14 UTC+0000
0xfffffa8002bf7280 svchost.exe            1092    464     18      276      0      0 2020-12-04 23:45:14 UTC+0000
0xfffffa8002cc4060 svchost.exe             772    464     13      318      0      0 2020-12-04 23:45:15 UTC+0000
0xfffffa8002c70350 wmpnetwk.exe           1088    464     13      402      0      0 2020-12-04 23:45:15 UTC+0000
0xfffffa8000e03b30 SearchIndexer.         1864    464     11      620      0      0 2020-12-04 23:45:16 UTC+0000
0xfffffa8000ef3820 svchost.exe            2088    464      4      167      0      0 2020-12-04 23:45:52 UTC+0000
0xfffffa8000dfb060 taskeng.exe            2928    860      5       81      0      0 2020-12-04 23:55:15 UTC+0000
0xfffffa8002be5340 SearchProtocol         2072   1864      8      279      0      0 2020-12-04 23:57:11 UTC+0000
0xfffffa8000e974e0 SearchFilterHo         2064   1864      5       96      0      0 2020-12-04 23:57:11 UTC+0000
```

We've already noticed from initial analysis that there is some `APK` file on the target, so we need to get that.

First we tried generic

```
volatility_2.6.exe -f spyagency3.img --profile Win7SP1x64 dumpfiles --dump-dir files
```

But it just dropped lots of windows exe/dlls, and not the zipped APK we wanted.

Then we did:

```
volatility_2.6.exe -f spyagency3.img --profile Win7SP1x64 filescan
```

And we got some interesting hits with `app-release.apk`.
We then used the offsets to dump those specific entries and one worked:

```
volatility_2.6.exe -f spyagency3.img --profile Win7SP1x64 dumpfiles -Q 0x000000003fefb8c0 --dump-dir files
```

From this we finally have the [apk](app-release.apk.zip).

### APK analysis

It's a bit weird re-packed apk, so we can extract it and then ZIP again just the contents if we want to try running it, but it's not useful.
We dropped this into BytecodeViewer just to see that the app does literally nothing.

But we need some `coordinates`, so we look around and there is `app-release/res/drawable/coordinates_can_be_found_here.jpg` file:

![](coordinates_can_be_found_here.jpg)

Now you could be thinking that we need to find the location shown on the picture, but nope.
If you look at the file via hexeditor there is:

```
˙Ř˙ŕ..JFIF..........˙ţ.4-coordinates=44.44672703736637, 26.098652847616506˙Ű.„..
```

So we have 44.44672703736637, 26.098652847616506 and dropped into google maps we get https://www.google.com/maps/place/44%C2%B026'48.2%22N+26%C2%B005'55.2%22E/@44.446727,26.0964641,17z/data=!3m1!4b1!4m5!3m4!1s0x0:0x0!8m2!3d44.446727!4d26.0986528

Which is a pizza hut in Bucharest.

## Guessing the flag

Last step was just to guess what author had in mind by `location name from coordinates in lowercase`, but eventually we guess `pizzahut` and submit `ctf{a939311a5c5be93e7a93d907ac4c22adb23ce45c39b8bfe2a26fb0d493521c4f}`
