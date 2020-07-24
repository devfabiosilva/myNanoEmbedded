; #
; #	AUTHOR: Fábio Pereira da Silva
; #	YEAR: 2019
; #	LICENSE: MIT
; #	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
; #
; #Fri Aug 09 2019 18:27:10 -03
; ## Implementation of big number 288 bit used in Nano Cryptocurrency C Library for IA64 architechture

#if F_ARM_A|F_ARM_M|F_THUMB

 #ifdef F_ARM_A
  .arch armv7-a
 #else
  .arch armv7-m
 #endif

 #ifdef F_THUMB
  .thumb
  .thumb_func
 #else
  .arm
 #endif

.text
.global f_add_bn_288_le
.align 1
.type f_add_bn_288_le, %function

f_add_bn_288_le:

 #ifdef F_THUMB

   push {r0, r1, r2, r4, r5, r6, r7, lr}

   ldr r4, [sp, #32]

   mov r7, #0

f_loop:

   ldr r5, [r0, #0]
   ldr r6, [r1, #0]
   add r5, r4
   adc r5, r6
   str r5, [r2, #0]

   ldr r5, [r0, #4]
   ldr r6, [r1, #4]
   adc r5, r6
   str r5, [r2, #4]

   ldr r5, [r0, #8]
   ldr r6, [r1, #8]
   adc r5, r6
   str r5, [r2, #8]

   ldr r5, [r0, #12]
   ldr r6, [r1, #12]
   adc r5, r5, r6
   str r5, [r2, #12]

   and r7, r7
   bne p1

   mov r4, #1
   bcs p1_1
   mov r4, #0

p1_1:

   add r0, r0, #16
   add r1, r1, #16
   add r2, r2, #16

   mov r7, #1

   b f_loop

p1:

   ldr r5, [r0, #16]
   ldr r6, [r1, #16]
   adc r5, r5, r6
   str r5, [r2, #16]

   and r3, r3
   beq p3
   bcs p2
   mov r7, #0

p2:

   str r7, [r3]

p3:

   pop {r0, r1, r2, r4, r5, r6, r7, pc}

 #else

   push {r0, r1, r2, r3, lr}

   ldr r2, [r0]

   orr r1, r2, lsl #11
   str r1, [r0]

   ldr r3, [r0, #4]
   mov r1, r3, lsl #11
   orr r1, r2, lsr #21
   str r1, [r0, #4]

   ldr r2, [r0, #8]
   mov r1, r2, lsl #11
   orr r1, r3, lsr #21
   str r1, [r0, #8]

   ldr r3, [r0, #12]
   mov r1, r3, lsl #11
   orr r1, r2, lsr #21
   str r1, [r0, #12]

   ldr r2, [r0, #16]
   mov r1, r2, lsl #11
   orr r1, r3, lsr #21
   str r1, [r0, #16]

   ldr r3, [r0, #20]
   mov r1, r3, lsl #11
   orr r1, r2, lsr #21
   str r1, [r0, #20]

   ldr r2, [r0, #24]
   mov r1, r2, lsl #11
   orr r1, r3, lsr #21
   str r1, [r0, #24]

   ldr r3, [r0, #28]
   mov r1, r3, lsl #11
   orr r1, r2, lsr #21
   str r1, [r0, #28]

   ldr r2, [r0, #32]
   mov r1, r2, lsl #11
   orr r1, r3, lsr #21
   str r1, [r0, #32]

   pop {r0, r1, r2, r3, pc}

 #endif

.size f_add_bn_288_le, .-f_add_bn_288_le

 #ifdef F_ARM_A
  .arch armv7-a
 #else
  .arch armv7-m
 #endif

 #ifdef F_THUMB
  .thumb
  .thumb_func
 #else
  .arm
 #endif

.text
.global f_sl_elv_add_le
.align 1
.type f_sl_elv_add_le, %function

f_sl_elv_add_le:

 #ifdef F_THUMB

   push {r0, r1, r2, r3, lr}

   ldr r2, [r0]

   lsl r3, r2, #11
   orr r1, r3
   str r1, [r0]
   lsr r3, r2, #21

   ldr r2, [r0, #4]
   lsl r1, r2, #11
   orr r1, r3
   str r1, [r0, #4]
   lsr r3, r2, #21

   ldr r2, [r0, #8]
   lsl r1, r2, #11
   orr r1, r3
   str r1, [r0, #8]
   lsr r3, r2, #21

   ldr r2, [r0, #12]
   lsl r1, r2, #11
   orr r1, r3
   str r1, [r0, #12]
   lsr r3, r2, #21

   ldr r2, [r0, #16]
   lsl r1, r2, #11
   orr r1, r3
   str r1, [r0, #16]
   lsr r3, r2, #21

   ldr r2, [r0, #20]
   lsl r1, r2, #11
   orr r1, r3
   str r1, [r0, #20]
   lsr r3, r2, #21

   ldr r2, [r0, #24]
   lsl r1, r2, #11
   orr r1, r3
   str r1, [r0, #24]
   lsr r3, r2, #21

   ldr r2, [r0, #28]
   lsl r1, r2, #11
   orr r1, r3
   str r1, [r0, #28]
   lsr r3, r2, #21

   ldr r2, [r0, #32]
   lsl r1, r2, #11
   orr r1, r3
   str r1, [r0, #32]

   pop {r0, r1, r2, r3, pc}

 #else

   push {r0, r1, r2, r3, lr}

   ldr r2, [r0]

   orr r1, r2, lsl #11
   str r1, [r0]

   ldr r3, [r0, #4]
   mov r1, r3, lsl #11
   orr r1, r2, lsr #21
   str r1, [r0, #4]

   ldr r2, [r0, #8]
   mov r1, r2, lsl #11
   orr r1, r3, lsr #21
   str r1, [r0, #8]

   ldr r3, [r0, #12]
   mov r1, r3, lsl #11
   orr r1, r2, lsr #21
   str r1, [r0, #12]

   ldr r2, [r0, #16]
   mov r1, r2, lsl #11
   orr r1, r3, lsr #21
   str r1, [r0, #16]

   ldr r3, [r0, #20]
   mov r1, r3, lsl #11
   orr r1, r2, lsr #21
   str r1, [r0, #20]

   ldr r2, [r0, #24]
   mov r1, r2, lsl #11
   orr r1, r3, lsr #21
   str r1, [r0, #24]

   ldr r3, [r0, #28]
   mov r1, r3, lsl #11
   orr r1, r2, lsr #21
   str r1, [r0, #28]

   ldr r2, [r0, #32]
   mov r1, r2, lsl #11
   orr r1, r3, lsr #21
   str r1, [r0, #32]

   pop {r0, r1, r2, r3, pc}

 #endif

.size f_sl_elv_add_le, .-f_sl_elv_add_le

#elif F_IA64

.text
.globl	f_add_bn_288_le
.type	f_add_bn_288_le, @function
.align 8

f_add_bn_288_le:

   clc
   movl %r8d, %r8d
   andl %r8d, %r8d
   jz a1
   stc

a1:
   movq (%rdi), %rax
   adcq (%rsi), %rax
   movq %rax, (%rdx)

   movq 8(%rdi), %rax
   adcq 8(%rsi), %rax
   movq %rax, 8(%rdx)

   movq 16(%rdi), %rax
   adcq 16(%rsi), %rax
   movq %rax, 16(%rdx)

   movq 24(%rdi), %rax
   adcq 24(%rsi), %rax
   movq %rax, 24(%rdx)

   movl 32(%rdi), %eax
   adcl 32(%rsi), %eax
   movl %eax, 32(%rdx)

   movl $0, %eax
   jnc p1
   movl $1, %eax

p1:
   test %rcx, %rcx
   jz p2
   movl %eax, (%rcx)

p2:
   ret

.size f_add_bn_288_le, .-f_add_bn_288_le

.text
.globl f_sl_elv_add_le
.type f_sl_elv_add_le, @function
.align 8

f_sl_elv_add_le:

/*
; I Really don't know why IA64 does not implement this function shifting bits in 64 bit mode.
; Maybe OS running in a protected mode?
   pushq %rax
   pushq %rbx

   movl %esi, %esi

   movq (%rdi), %rax
   movq %rax, %rbx
   shrq $21, %rbx
   shlq $11, %rax
   orq %rsi, %rax
   movq %rax, (%rdi)

   movq 8(%rdi), %rax
   movq %rax, %rsi
   shrq $21, %rsi
   shlq $11, %rax
   orq %rbx, %rax
   movq %rax, 8(%rdi)

   movq 16(%rdi), %rax
   movq %rax, %rbx
   shrq $21, %rbx
   shlq $11, %rax
   orq %rsi, %rax
   movq %rax, 16(%rdi)

   movq 24(%rdi), %rax
   movq %rax, %rsi
   shrq $21, %rsi
   shlq $11, %rax
   orq %rbx, %rax
   movq %rax, 24(%rdi)

   movl 32(%rdi), %eax
   shll $11, %eax
   orl %esi, %eax
   movl %eax, 32(%rdi)

   popq %rbx
   popq %rax
   retq
*/

   pushq %rax
   pushq %rbx

   movl %esi, %esi

   movl (%rdi), %eax
   movl %eax, %ebx
   shll $11, %eax
   shrl $21, %ebx
   orl %esi, %eax
   movl %eax, (%rdi)

   movl 4(%rdi), %eax
   movl %eax, %esi
   shll $11, %eax
   shrl $21, %esi
   orl %ebx, %eax
   movl %eax, 4(%rdi)

   movl 8(%rdi), %eax
   movl %eax, %ebx
   shll $11, %eax
   shrl $21, %ebx
   orl %esi, %eax
   movl %eax, 8(%rdi)

   movl 12(%rdi), %eax
   movl %eax, %esi
   shll $11, %eax
   shrl $21, %esi
   orl %ebx, %eax
   movl %eax, 12(%rdi)

   movl 16(%rdi), %eax
   movl %eax, %ebx
   shll $11, %eax
   shrl $21, %ebx
   orl %esi, %eax
   movl %eax, 16(%rdi)

   movl 20(%rdi), %eax
   movl %eax, %esi
   shll $11, %eax
   shrl $21, %esi
   orl %ebx, %eax
   movl %eax, 20(%rdi)

   movl 24(%rdi), %eax
   movl %eax, %ebx
   shll $11, %eax
   shrl $21, %ebx
   orl %esi, %eax
   movl %eax, 24(%rdi)

   movl 28(%rdi), %eax
   movl %eax, %esi
   shll $11, %eax
   shrl $21, %esi
   orl %ebx, %eax
   movl %eax, 28(%rdi)

   movl 32(%rdi), %eax
   shll $11, %eax
   orl %esi, %eax
   movl %eax, 32(%rdi)

   popq %rbx
   popq %rax
   retq

.size f_sl_elv_add_le, .-f_sl_elv_add_le

#elif F_XTENSA

.text
.global f_add_bn_288_le
.align 4
.type f_add_bn_288_le, @function

f_add_bn_288_le:

   entry sp, 16

   mov.n a10, a2
   mov.n a11, a3
   mov.n a12, a4
   mov.n a13, a5
   mov.n a9,  a6

   l32i.n a2, a10, 0
   l32i.n a3, a10, 4
   l32i.n a4, a10, 8
   l32i.n a5, a10, 12

   movi.n a14, 0

f_add_bn_288_le_RET:

   add.n a2, a2, a9
   mov.n a8, a9
   movi.n a9, 1
   bltu a2, a8, k1
   movi.n a9, 0

k1:
   l32i.n a8, a11, 0
   add.n a2, a2, a8
   bnez a9, p1
   movi.n a9, 1
   bltu a2, a8, p1
   movi.n a9, 0

p1:
   add.n a3, a3, a9
   mov.n a8, a9
   movi.n a9, 1
   bltu a3, a8, p2
   movi.n a9, 0

p2:
   l32i.n a8, a11, 4
   add.n a3, a3, a8
   bnez a9, p3
   movi.n a9, 1
   bltu a3, a8, p3
   movi.n a9, 0

p3:
   add.n a4, a4, a9
   mov.n a8, a9
   movi.n a9, 1
   bltu a4, a8, p4
   movi.n a9, 0

p4:
   l32i a8, a11, 8
   add.n a4, a4, a8
   bnez a9, p5
   movi.n a9, 1
   bltu a4, a8, p5
   movi.n a9, 0

p5:
   add.n a5, a5, a9
   mov.n a8, a9
   movi.n a9, 1
   bltu a5, a8, p6
   movi.n a9, 0

p6:
   l32i a8, a11, 12
   add.n a5, a5, a8
   bnez a9, p7a
   movi.n a9, 1
   bltu a5, a8, p7a
   movi.n a9, 0

p7a:
   bnez a14, p7
   movi.n a14, 1
   addi a11, a11, 16

   s32i.n a2, a12, 0
   s32i.n a3, a12, 4
   s32i.n a4, a12, 8
   s32i.n a5, a12, 12

   l32i.n a2, a10, 16
   l32i.n a3, a10, 20
   l32i.n a4, a10, 24
   l32i.n a5, a10, 28
   l32i.n a6, a10, 32     
   j f_add_bn_288_le_RET

p7:
   add.n a6, a6, a9
   mov.n a8, a9
   movi.n a9, 1
   bltu a6, a8, p8
   movi.n a9, 0

p8:
   l32i a8, a11, 16
   add.n a6, a6, a8

   beqz a13, p10

   bnez a9, p9
   movi.n a9, 1
   bltu a6, a8, p9
   movi.n a9, 0

p9:
   s32i.n a9, a13, 0

p10:
   s32i.n a2, a12, 16
   s32i.n a3, a12, 20
   s32i.n a4, a12, 24
   s32i.n a5, a12, 28
   s32i.n a6, a12, 32
   retw.n

.size f_add_bn_288_le, .-f_add_bn_288_le

.text
.global f_sl_elv_add_le
.align 4
.type f_sl_elv_add_le, @function

f_sl_elv_add_le:

   entry sp, 16
   mov.n a11, a2
   mov.n a12, a3

   l32i a2, a11, 0
   l32i a3, a11, 4
   l32i a4, a11, 8
   l32i a5, a11, 12
   l32i a6, a11, 16
   l32i a7, a11, 20
   l32i a8, a11, 24
   l32i a9, a11, 28
   l32i a10, a11, 32

   slli a10, a10, 11
   mov.n a13, a9
   slli a9, a9, 11
   extui a14, a13, 21, 11
   or a10, a10, a14
   mov.n a13, a8
   slli a8, a8, 11
   extui a14, a13, 21, 11
   or a9, a9, a14
   mov.n a13, a7
   slli a7, a7, 11
   extui a14, a13, 21, 11
   or a8, a8, a14
   mov.n a13, a6
   slli a6, a6, 11
   extui a14, a13, 21, 11
   or a7, a7, a14
   mov.n a13, a5
   slli a5, a5, 11
   extui a14, a13, 21, 11
   or a6, a6, a14
   mov.n a13, a4
   slli a4, a4, 11
   extui a14, a13, 21, 11
   or a5, a5, a14
   mov.n a13, a3
   slli a3, a3, 11
   extui a14, a13, 21, 11
   or a4, a4, a14
   mov.n a13, a2
   slli a2, a2, 11
   extui a14, a13, 21, 11
   or a3, a3, a14
   or a2, a2, a12

   s32i a2, a11, 0
   s32i a3, a11, 4
   s32i a4, a11, 8
   s32i a5, a11, 12
   s32i a6, a11, 16
   s32i a7, a11, 20
   s32i a8, a11, 24
   s32i a9, a11, 28
   s32i a10, a11, 32

   retw.n

.size f_sl_elv_add_le, .-f_sl_elv_add_le

#else
 #error "Can't determine hardware architecture"
#endif

