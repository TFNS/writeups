# Transformer: The Guardian Knight - Balsn CTF 2020 (misc, 626p, 10 solved)
## Introduction

This challenge implements a web server in NodeJS.

This web server sends a flag :
```javascript
const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`The flag is ${flag}.`);
});
```

There is a Web-Application Firewall that prevents the flag from being sent :
```javascript
class WAF extends Transform {
    _transform (data, encoding, callback) {
        data = data.toString('ascii').replace(/BALSN{([^}]*)/g, (m, c) =>
            'BALSN{' + Array(c.length).fill('REDACTED_').join('').slice(0, c.length)
        )
        callback(null, data)
    }
};
```

## Attack

HTTP/1.1 supports requests pipelining, e.g. it is possible to send multiple
requests before the server sends a response.

Answering to a lot of requests will fill an internal buffer on the server. The
WAF will then read from this buffer. Since only a fixed number of bytes will be
read by the WAF, it is possible to fill this buffer up to a point where the WAF
will read an incomplete flag. The filter will thus not mask the flag.

```shell
yes $'GET / HTTP/1.1\r\n\r' | nc waf.balsnctf.com 8889 \
	| fgrep flag \
	| fgrep -v REDACTED
```

**Flag**: `BALSN{!+-WTF_is_this_WAF-+!}`
