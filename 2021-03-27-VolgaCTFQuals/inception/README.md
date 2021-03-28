# Inception (stegastics, 454p, 2 solved)

## Description

```
A dream within a dream? Two levels?..
```


## Task analysis

We start off with a [png file](1st_level.png).

Quick look at this file showed us a couple of interesting ideas:

- LSB on blue plane in stegsolve looked very weird, potentially something hidden there
- PNG contained a TIFF file embedded

We initially didn't notice anythin interesting in the LSB stream and focused on the TIFF file, which was broken, but contained a JPG payload, which we extracted and tried to analyse for quite some time...
This was all in vain, the LSB was the important piece.

## Solution

### LSB blue plane

From LSB on blue color we can extract a [ZIP archive](lsb.zip) with MIDI file inside.

### Midi file

By opening midi file in audacity we can see that there are only 2 types of notes

- high
- low

And duration is either `100` or `200`.
There are about 3 times less `high` than `low` so definitely not binary.
Also `high` has never duration `200`.
From this we came to the conclusion that it's Morse or something similar.

We guessed that it will be Morse with `high` as separator of letters and duration `100` will be `.` and `200` will be `-`.
We wrote a simple script to transpose:

```python
    from midi import FileReader
    from crypto_commons.generic import chunk_with_remainder
    
    file = "2ndlevel.mid"
    midifile = open(file, 'rb')
    reader = FileReader()
    pattern = reader.parse_file_header(midifile)
    events = []
    for track in pattern:
        reader.parse_track(midifile, track)
        for event in track[:-1]:
            events.append((event.tick, event.pitch))
    chunks = chunk_with_remainder(events, 2)
    payload = ''
    for first, second in chunks:
        if first[1] == 49:
            payload += ' '
        else:
            if second[0] == 200:
                payload += '-'
            else:
                payload += '.'
    print(payload)
```

And got back a nice [Morse code transcript](morse.txt).

### Morse code

Now we can turn this into letters (eg. with CyberChef) to get some [base26-like file](base26.txt).

### Base26

It was not exactly clear what to do with this, but eventually we guessed to turn this into number as base26 and then this number to hex and decode as binary stream.
Once we do this, we get a [pdf file](egypt.pdf)

### PDF file

PDF contains text from Wikipedia on Egypt.
Our guess was to compare contents, but it's painful because of not respected whitespaces, UTF characters, removed citations etc.

We wrote a simple code to "cleanup":

```python
    data = re.sub('\[.+?]', '', data)
    data = data.replace("\r\n", ' ')
    data = data.replace("\n", ' ')
    data = data.replace("  ", ' ')
    data = data.replace("  ", ' ')
    data = data.replace("  ", ' ')
    data = data.replace("  ", ' ')
    return data
```

And then to compare text copied from PDF with what's on wikipedia:

```python
    a = 0
    b = 0
    binary = ''
    while a < len(d1) and b < len(d2):
        if d1[a] != d2[b]:
            print(d1[a - 10:a + 40], d2[b - 10:b + 40])
            break
```

The differences we found were missing `.`
We decided to collect this as mark missing as 0 and existing `.` as 1:

```python
    a = 0
    b = 0
    binary = ''
    print(d1.count('.'))
    while a < len(d1) and b < len(d2):
        if d1[a] != d2[b]:
            print(d1[a - 10:a + 40], d2[b - 10:b + 40])
            a += 1
            b += 2
            binary += '0'
        else:
            if d1[a] == '.':
                binary += '1'
            a += 1
            b += 1
    print(binary)
```

Now if we just convert this to bytes `print(long_to_bytes((int(binary, 2))))` we get: `VolgaCTF{60wnw4r6_15_7h3_0nly_w4y_f0rw4r6}`
