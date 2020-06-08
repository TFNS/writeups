# Fortune Cookie - 2020 Defenit CTF (web, 507p, 15 solved)
## Introduction

Fortune Cookie is a web task.

A full docker environment is given. It contains a node app container and a
MongoDB database container.

The app allows clients to log in, write information to the database and read
what informations they stored.

The client's username is stored in a signed cookie.

The flag can be obtained if the client can provide a number such that
`Math.floor(Math.random() * 0xdeaaaadbeef) === ${favoriteNumber}` holds true.

## Source code review

The `login` endpoint will allow any username, even if it is not a string. This
username is then serialized and signed in a cookie.

```javascript
app.post('/login', (req, res) => {
	let { username } = req.body;

	res.cookie('user', username, { signed: true });
	res.redirect('/');
});
```

The `write` endpoint allows a user to insert data in a collection. Both the
`author` and `content` values can be objects, but there is no use to this.

The `view` endpoint shows a specific post. No vulnerability was identified on
this endpoint.

The `posts` endpoint reads the user's posts. It uses the signed cookie to find
every posts made by the current user. There is a NoSQL injection.

```javascript
app.get('/posts', (req, res) => {

    let client = new MongoClient(MONGO_URL, { useNewUrlParser: true });
    let author = req.signedCookies.user;

    if (typeof author === 'string') {
        author = { author };
    }

    client.connect(function (err) {

        if (err) throw err;

        const db = client.db('fortuneCookie');
        const collection = db.collection('posts');

        collection
            .find(author)
            .toArray()
            .then((posts) => {
                res.render('posts', { posts })
            }
            );

        client.close();

    });

});
```

The flag is not in the database. Peeking at other users' payload won't be
helpful.

The `flag` endpoint retrieves a parameter and check if
`Math.floor(Math.random() * 0xdeaaaadbeef)` is equal to this parameter. The
parameter is casted to int. This endpoint is not vulnerable.


## Exploitation

As mentionned above, the `posts` endpoint is vulnerable to a NoSQL injection. It
is possible to execute Javascript in the same process as the one used to check
if the user's number is correct for the `flag` endpoint.

The random number generator used by MongoDB is `XorShift128+`. Attacks exist to
retrieve its internal state. As interesting as this path would have been, this
is not the solution.

Instead, it is possible to redefine the `Math.floor` function to return a
constant. This can be done by login in with a username of
`username[$where]=(Math.floor=()=>0x586552),false`. This will make it always
return the number 5793106.

Two quick requests to `/posts` and to `/flag?favoriteNumber=5793106` using this
username will print the flag.

**Flag**: `Defenit{c0n9r47ula7i0n5_0n_y0u2_9o0d_f02tun3_haHa}`
