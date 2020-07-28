# Serial (misc, 63p, 108 solved)

In the task we can access a web-based serial number checker.
We also have access to the [code](1.js).

It might seem trivial, because the code is just:

```js
if ( (a>0 && a < 1000000) & (b>0 && b < 1000000) & (c>0 && c < 1000000) & a*a*a + b*b*b == c*c*c){
  res.writeHead(200,{"Content-Type": "text/html"});
  res.write(flag);
  res.end();
}
```

So we just need to find 3 numbers which match given condition.
Unfortunately, this is actually contradicting Fermat's Last Theorem https://en.wikipedia.org/wiki/Fermat%27s_Last_Theorem so there needs to be something fishy here.

We quickly stumble upon `Number.MAX_SAFE_INTEGER` value in JS https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER

Apparently internally integers are stored as floats, and thus have precision limit, and above this particular value comparison might find two different numbers to be equal.

We now just need to compute 3rd integer root of this value and set `a=c=iroot(Number.MAX_SAFE_INTEGER, 3)+1` and `b=1`.

This way `a**3` and `c**3` will be above `Number.MAX_SAFE_INTEGER` and if we just add `1` the comparison will still show as equal.

We send `a=c=208064` and `b=1` and get `cybrics{CYB3R_M47H_15_57R4Ng3}`
