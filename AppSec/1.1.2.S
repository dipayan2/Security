.global your_asm_fn
.section .text

your_asm_fn:
push    %ebp
mov     %esp,%ebp
sub     0x8,%esp
mov     0xc001f00d,(%esp)
sub     0x4,%esp
mov     0xc105ed,(%esp)
sub     0x4,%esp
mov     0xacce55ed,(%esp)
call    practice
leave
ret
