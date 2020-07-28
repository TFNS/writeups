# Krevedka (forensics, 50p, 164 solved)

In the task we get a 300MB pcap file to analyse (sorry, won't include it here).
We know that the user who got hacked had login `caleches` and we're supposed to find the attacker's login.

If we look for victim login we find:

```
POST /login HTTP/1.1
Host: kr3vedko.com
User-Agent: UCWEB/2.0 (Linux; U; Opera Mini/7.1.32052/30.3697; www1.smart.com.ph/; GT-S5360) U2/1.0.0 UCBrowser/9.8.0.534 Mobile
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Cookie: session=b75d53bb-1326-4d78-aedf-9bd92e237fbf
Content-Length: 39
Content-Type: application/x-www-form-urlencoded

login=caleches&password=%22+or+1%3D1+--
```

so a classic SQLi attack vector.

The idea to find the real attacker is pretty simple: notice that there was already a session cookie included in the request! Perhaps it was set during previous attacker login?
Sadly, not the case.

On top of that attacker had some really interesting UA string, not very common.
If we look for the UA we can find:

```
POST /login HTTP/1.1
Host: kr3vedko.com
User-Agent: UCWEB/2.0 (Linux; U; Opera Mini/7.1.32052/30.3697; www1.smart.com.ph/; GT-S5360) U2/1.0.0 UCBrowser/9.8.0.534 Mobile
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Cookie: session=d4c78f87-b88c-4833-8851-ffd12856cf39
Content-Length: 35
Content-Type: application/x-www-form-urlencoded

login=micropetalous&password=1221nr
```

And this is our flag: `cybrics{micropetalous}`
