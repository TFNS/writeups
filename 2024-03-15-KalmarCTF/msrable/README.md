# msrable (pwn, 490p, 9 solved)

## Description

```
I hate having to use sudo every time I want to change the MSRs. Let's just make it global writable! I'm sure that won't cause any security issues...
```

We're given a 6.7.5 Linux kernel with the following patch applied:

```diff
diff --git a/arch/x86/kernel/msr.c b/arch/x86/kernel/msr.c
--- a/arch/x86/kernel/msr.c
+++ b/arch/x86/kernel/msr.c
@@ -208,9 +208,6 @@ static int msr_open(struct inode *inode, struct file *file)
        unsigned int cpu = iminor(file_inode(file));
        struct cpuinfo_x86 *c;
 
-       if (!capable(CAP_SYS_RAWIO))
-               return -EPERM;
-
        if (cpu >= nr_cpu_ids || !cpu_online(cpu))
                return -ENXIO;  /* No such CPU */
```

Unprivileged users have now full MSRs read/write.

## Solution

Kudos to XeR for the original exploit.

### Leak

Leaking the base address of the kernel is the easy part. We can read the content of the `MSR_LSTAR` MSR that contains the address of `entry_SYSCALL_64` code.
We can deduce the kernel base address with the address read.

### Code execution

The target is to get code execution by overwriting the content of `core_pattern`, which is the command that will be executed as root when a core dump occurs (eg. if a user program segfaults). We will overwrite the `core_pattern` string with `|/bin/chmod 777 /flag`.

We can easily control RIP by overwriting `MSR_LSTAR` and triggering a `syscall` instruction, but KPTI, SMEP and SMAP will bother a bit.

Since `syscall` doesn't change the stack pointer (the kernel syscall handler is supposed to do so), we can build a ROP chain on the user stack that will overwrite `core_pattern` characters one by one.

Here is the strategy:

1. Before crafting and calling the ROP chain, we can unset the 18th bit of the `MSR_FMASK` MSR (or `MSR_SYSCALL_MASK` as it's called in the kernel). This is the `AC (Alignment check)` flag [0], it's used to determine if `SMAP` is enabled (`ELFAGS.AC` set means that SMAP is disabled). We then emulate a `stac` instruction in userspace to set the AC flag that won't be unset when entering in kernel with `syscall`.

2. The second barrier is `KPTI` (Kernel page-table isolation). After overwriting `MSR_LSTAR` and triggering a syscall, the `cr3` register still points to user pagetable, that reduces a lot the memory we can access to. It means we can't access to gadgets in kernel mapped memory. Fortunately there is a gadget at `paranoid_entry+0x45` that changes `cr3` to get access to kenel pagetable. This gadget ends with a `ret` allowing to start executing the ROP chain in user stack. We can put write this gadget address in `MSR_LSTAR` as an exploit entry point.

3. We plan to execute code from the user program, thus we have to disable `SMEP` as well. To do so, we can call a gadget at `core_restore+0x1a` that basically does `mov cr4, rbx ; ... ; jmp r8`. So we can start the ROP chain with a `pop rbx ; ret` to add the value we want in cr4 so that SMEP (and SMAP) is disabled. We also need to put 0 in rdx.

4. We can now modify `core_pattern` value. We can use a `mov byte [rdx], ax ; ret` gadget, with `core_pattern` address in rdx and the new character in ax. We will overwrite byte after byte, so we actually write at `core_pattern+i` the value of `payload+i` where `payload` is the string we want to put in core_pattern, and i the index of the char.

5. The goal is now to write back the original value of `MSR_LSTAR` to make the system usable again. To do so, we prepare a `wrmsr` payload in user code, that we will be call in our ROP chain with CPL = 0. For this, we need to change cr3 again to put the user pagetable. Fortunately again, there is a `mov rdi, cr3 ; or rdi, 0x1000 ; mov cr3, rdi ; iretq` gadget at 0x80158b offset.
With the userspace cr3 set, we can call user code with the `iretq` and call `wrmsr` to put the original `MSR_LSTAR`.

6. Finally, we can cleanly return to userspace with a `sysretq` after calling `wrmsr`.

7. Once we looped over all the previous steps to overwrite the whole `core_pattern`, we simply need to trigger a core dump by making the exploit code segfaulting.


[0] https://wiki.osdev.org/CPU_Registers_x86#EFLAGS_Register