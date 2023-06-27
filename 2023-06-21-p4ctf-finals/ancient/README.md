# Ancient kingdom (web, 4 solves, 421 points)

## Introduction

We get a link to a webpage and that's about it.
Chrome displays some HTTP2 error when trying to access it.
There is also `/flag` endpoint which doesn't show errors on Chrome.

## Analysis

We spent quite some time, reading too much into the "ancient" part in the title.
We assumed it means we're supposed to do some HTTP 1.0 / 1.1 trick, perhaps request smuggling based on some invalid header handling (eg. chunked encoding) between application and reverse proxy.
The task description was also strongly hinting HTTP 2, so we though that maybe there is some weird upgrade/downgrade or some smuggling related to mixing 2.0 and 1.X protocols.
It was also pretty weird that `/flag` didn't error like `/`.

## Solution

While trying to fuzz the server we started using some python http2 client and we noticed some strange things.
The `/` didn't show any errors and then we also spotted some strange `push` stream events.
So we just left a loop which dumps all output we get from the socket:

```python
import h2.connection
import h2.events
import socket
import ssl

SERVER_NAME = 'ancient-kingdom.zajebistyc.tf'
SERVER_PORT = 443

socket.setdefaulttimeout(15)
ctx = ssl._create_unverified_context()
ctx.set_alpn_protocols(['h2'])

s = socket.create_connection((SERVER_NAME, SERVER_PORT))
s = ctx.wrap_socket(s, server_hostname=SERVER_NAME)

c = h2.connection.H2Connection()
c.initiate_connection()
s.sendall(c.data_to_send())

headers = [
    (':method', 'GET'),
    (':path', '/'),
    (':authority', SERVER_NAME),
    (':scheme', 'https'),
]
c.send_headers(1, headers, end_stream=False)
c.send_headers(3, [
    (':method', 'GET'),
    (':path', '/flag'),
    (':authority', SERVER_NAME),
    (':scheme', 'https'),
], end_stream=False)
c.send_headers(5, [
    (':method', 'GET'),
    (':path', '/'),
    (':authority', SERVER_NAME),
    (':scheme', 'https'),
], end_stream=True)
s.sendall(c.data_to_send())

body = b''
while True:
    data = s.recv(65536 * 1024)
    if not data:
        break
    print('data', data)
    events = c.receive_data(data)
    for event in events:
        print(event)
        if isinstance(event, h2.events.DataReceived):
            c.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            body += event.data
        if isinstance(event, h2.events.StreamEnded):
            # ignore
            break
        if isinstance(event, h2.events.PushedStreamReceived):
            break
    s.sendall(c.data_to_send())
    print(body)
```

And in some push stream we got: `p4{C7Hr0m3_106_d1s4bl3d_HTTp2_Pu$h}`
