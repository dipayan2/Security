.global your_asm_fn
.section .text

your_asm_fn:
push    %ebp
mov     %esp,%ebp
sub     0x8,%esp
xor     %eax,%eax
add     0xc001f00d,%eax    
mov     %eax,(%esp)
sub     0x4,%esp
xor     %eax,%eax
add     0xc105ed,%eax
mov     %eax,(%esp)
sub     0x4,%esp
xor     %eax,%eax
add     0xacce55ed,%eax
mov     %eax,(%ebp)
call    practice
leave
ret
