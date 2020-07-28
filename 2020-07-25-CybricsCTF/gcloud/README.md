# Google Cloud (misc, 96p, 83 solved)

In the task we get a [pcap](gcloud.pcap).
It seems the pcap contains capture of work of https://github.com/yarrick/pingfs

The idea is that data are partitioned and sent in ICMP Ping pattern payloads, and when they come back, you send them again.
This way, theoretically, you can store your data `in the network` (or rather in router buffers).

It's easy to notice that we have some text/source files and one binary-looking payload.
If we run binwalk it will tell us that there is JPEG file signature there.

We could probably try to read how this protocol works, but we're too lazy for that, so we just make some educated guesses.
It seems that packet sequence numbers are used to mark unique `file chunk` - the same sequence number seems to carry the same data.
Looking at the text files we can also notice that sequence numbers seems to follow the order of data chunks.

This means we can just grab all unique sequence numbers, read payloads for them, and re-assemble the files.
We didn't fogure out how to know which chunk belongs to given file, but fortunately there is only one binary file in transfer so we can just filter out chunks with only printable characters, an we should be left with our image data:

```python
import binascii

import pyshark

from crypto_commons.generic import is_printable


def main():
    pcap = pyshark.FileCapture("gcloud.pcap")
    chunks = OrderedDict()
    try:
        for pkt in pcap:
            if pkt.ip.host.show != '8.8.8.8': # skip responses
                data = binascii.unhexlify(pkt.icmp.data.raw_value)
                if not is_printable(data):
                    chunks[pkt.icmp.ident.show] = data
    except:
        pass
    print(len(chunks))
    print(chunks)
```

This way we manage to recover the image chunks.
Now we can just do:

```python
    output = open("result.jpg", 'wb')
    for c, data in chunks.items():
        if c != '0': # skip packets 0, they are some normal pings, not part of image
            print(c)
            output.write(data)
    output.close()
```

And we get:

![](result.jpg)

`cybrics{b3c4us3_PNG_is_p2oNoUnc3d_piNg}`
