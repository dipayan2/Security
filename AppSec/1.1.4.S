.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here
# Push *mp as "coolfood" in little-endian ASCII to the stack and store pointer in %eax
pushl $0x00000000
pushl $0x646f6f66
pushl $0x6c6f6f63
movl %esp, %eax

// Push 0xc105ed to stack and store pointer in %ebx
pushl $0xc105ed
movl %esp, %ebx

// Push arguments to practice right-to-left
pushl %eax
pushl %ebx
pushl $0xacce55ed
call practice

leave
ret
