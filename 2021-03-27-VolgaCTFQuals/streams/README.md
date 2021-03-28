# Streams (stegastics, 295p, 23 solved)

## Description

```
We really really need one of the files that were captured in these two .pcapng. It contains a string that starts with "VolgaCTF".

Is there any chance you could find it?
```


## Task analysis

In the task we get two pcaps, [one with FTP transfer](stream.pcap) and second one with [USB traffic](stream2.pcap).

First PCAP contains FTP transfer of a RAR archive, however there are lots of missing packets there.
From paths it's clear that RAR contains large directory tree with a txt file as leaf for each path.

If we dump RAR from pcap (at least the non-missing part), it asks for a password during extraction.

Second PCAP contains USB traffic from multiple different devices.

## Solution

This task was very fustrating because there is a lot of data and not a clear direction.
We will include only the needed steps, without all the weird ideas we had...

### Extract RAR password

We noticed that one of USB traffic streams was USB-HID device, so we run the script to extract potential keyboard keystrokes.
All other USB traffic streams are not useful at all.

First we dump the relevant data:

```
tshark -r ./stream.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata > usbPcapData
```

And recover keys:

```python
# coding=utf-8
KEY_CODES = {
    0x04: ['a', 'A'],
    0x05: ['b', 'B'],
    0x06: ['c', 'C'],
    0x07: ['d', 'D'],
    0x08: ['e', 'E'],
    0x09: ['f', 'F'],
    0x0A: ['g', 'G'],
    0x0B: ['h', 'H'],
    0x0C: ['i', 'I'],
    0x0D: ['j', 'J'],
    0x0E: ['k', 'K'],
    0x0F: ['l', 'L'],
    0x10: ['m', 'M'],
    0x11: ['n', 'N'],
    0x12: ['o', 'O'],
    0x13: ['p', 'P'],
    0x14: ['q', 'Q'],
    0x15: ['r', 'R'],
    0x16: ['s', 'S'],
    0x17: ['t', 'T'],
    0x18: ['u', 'U'],
    0x19: ['v', 'V'],
    0x1A: ['w', 'W'],
    0x1B: ['x', 'X'],
    0x1C: ['y', 'Y'],
    0x1D: ['z', 'Z'],
    0x1E: ['1', '!'],
    0x1F: ['2', '@'],
    0x20: ['3', '#'],
    0x21: ['4', '$'],
    0x22: ['5', '%'],
    0x23: ['6', '^'],
    0x24: ['7', '&'],
    0x25: ['8', '*'],
    0x26: ['9', '('],
    0x27: ['0', ')'],
    0x28: ['\n', '\n'],
    0x2C: [' ', ' '],
    0x2D: ['-', '_'],
    0x2E: ['=', '+'],
    0x2F: ['[', '{'],
    0x30: [']', '}'],
    0x32: ['#', '~'],
    0x33: [';', ':'],
    0x34: ['\'', '"'],
    0x36: [',', '<'],
    0x38: ['/', '?'],
    0x37: ['.', '>'],
    0x2b: ['\t', '\t'],
    0x4f: [u'→', u'→'],
    0x50: [u'←', u'←'],
    0x51: [u'↓', u'↓'],
    0x52: [u'↑', u'↑']
}
keyboard = """00:00:28:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:1a:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:13:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:1a:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:0b:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:14:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:16:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:07:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:0b:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:0f:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:13:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:24:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:0b:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:1b:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:23:00:00:00:00:00
00:00:00:00:00:00:00:00
00:00:26:00:00:00:00:00
00:00:00:00:00:00:00:00"""
datas = keyboard.split('\n')[:-1]
cursor_x = 0
cursor_y = 0
offset_current_line = 0
lines = ['', '', '', '', '']
output = ''

for data in datas:
    shift = (int(data.split(':')[0], 16) / 2) > 0
    key = int(data.split(':')[2], 16)
    if key == 0:
        continue
    if key not in KEY_CODES:
        print("missing ", key)
    if KEY_CODES[key][shift] == u'↑':
        lines[cursor_y] += output
        output = ''
        cursor_y -= 1
    elif KEY_CODES[key][shift] == u'↓':
        lines[cursor_y] += output
        output = ''
        cursor_y += 1
    elif KEY_CODES[key][shift] == u'→':
        cursor_x += 1
    elif KEY_CODES[key][shift] == u'←':
        cursor_x -= 1
    elif KEY_CODES[key][shift] == '\n':
        lines[cursor_y] += output
        cursor_x = 0
        cursor_y += 1
        output = ''
    else:
        output += KEY_CODES[key][shift]

print(output)
```

From this we get `wpwhqsdhlp7hx69`

### Recover RAR archive

Because there are missing chunks of the RAR we can't easily carve it out from the pcap or dump with wireshark.
The differences in the sequence numbers can tell us how much data we're missing, so we wrote a script to inflate missing parts with nullbytes:

```python
import pyshark


def main():
    buffer = b''
    pcap = pyshark.FileCapture("stream.pcap")
    next_sequence = 1
    for pkt in pcap:
        if pkt.highest_layer == 'FTP-DATA':
            if int(pkt.tcp.seq) != next_sequence:
                missing = int(pkt.tcp.seq) - next_sequence
                buffer += (b'\0' * missing)
            next_sequence = int(pkt.tcp.nxtseq)
            buffer += pkt.tcp.payload.binary_value
    pcap.close()
    open("out.rar", 'wb').write(buffer)


main()
```

This way we get a ~14MB archive.
Now we used WinRAR "repair archive" utility and got back RAR we could extract using password we had and get back quite large tree, although some pieces were missing.

### Find the flag!

Now we have thousands of files all with `haha, jebaited` and possibly one with flag.
We can run `grep "Volga" -R` or parse the RAR to find one file with different size and we get: `VolgaCTF{1T_w42_e45y_t0_cR4cK_8R0keN_r4R}`
