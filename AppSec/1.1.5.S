.global _main
.section .text

_main:

push    %ebp
mov     %esp,%ebp

# Your code here
# Push //bin/sh as LE-ASCII string to stack and move pointer to start into %ebx
pushl $0x00000000
pushl $0x68732f6e
pushl $0x69622f2f
movl %esp, %ebx

# envp is a nill pointer
pushl $0x00000000
movl %esp, %edx

# argv is an array with a pointer to the executable //bin/sh as first and only entry
pushl %ebx
movl %esp, %ecx

# initiate syscall interupt with code 0x80 (11 is the execve syscall number)
movl $11, %eax
int $0x80

leave
ret
