# Doubly deleted data (forensics, 330p, 260 solved)

## Description

```
We got a copy of an elusive hacker's home partition and gave it to someone back in HQ to analyze for us. We think the hacker deleted the file with the flag, but before our agent could find it, they accidentally deleted the copy of the partition! Now we'll never know what that flag was. :(
```

We get [some gzipped disk image](flash_drive.img.gz)

## Solution

Load this image into your favourite hexeditor and just look for flag format, or do `strings flash_drive.img | grep utflag` and you get:

```
utflag{data_never_disappears}
utflag{data_never_disappears}
echo "utflag{d@t@_never_dis@ppe@rs}" > real_flag.txt
utflag{data_never_disappears}
echo "utflag{d@t@_never_dis@ppe@rs}" > real_flag.txt
echo "utflag{d@t@_never_dis@ppe@rs}" > real_flag.txt
utflag{data_never_disappears}
echo "utflag{d@t@_never_dis@ppe@rs}" > real_flag.txt
echo "utflag{d@t@_never_dis@ppe@rs}" > real_flag.txt
utflag{data_never_disappears}
echo "utflag{d@t@_never_dis@ppe@rs}" > real_flag.txt
```

Submit `utflag{d@t@_never_dis@ppe@rs}`
