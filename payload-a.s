        .section .asheader

        .section .asentry
sfb:    b steal_frame_buffer
        @ sendupdate preamble---the bytes we overwrote
        @ in order to to put in the jump to the hook
        @ (hopefully they don't do anything pc-relative)
suaddr: .word 0
supr:   .word 0
        .word 0
        .word 0
        ldr pc, suaddr
        @ sendupdate hook---save the parameter values and finish the call
suprhk: adr ip, suarg1
        stmia ip, {r1-r3,lr}
        ldr lr, [sp, #0x0]
        str lr, suarg4
        adr lr, supo
        b supr
        @ storage for sendupdate params
suarg1: .word 0
suarg2: .word 0
suarg3: .word 0
sulr:   .word 0
suarg4: .word 0
        @ sendupdate postamble---give the stored params to C and return
supo:   push {r0-r4}
        adr ip, suarg1
        ldmia ip, {r0-r2}
        ldr r3, suarg4
        bl sendupdate_hook
        pop {r0-r4}
        ldr lr, sulr
        bx lr

        @ primitives for C, since we don't have a standard library
        .Section .text
        .global _syscall
_syscall:
        push {r4-r7}
        cpy r7, r0
        cpy r0, r1
        cpy r1, r2
        cpy r2, r3
        ldr r3, [sp, #16]
        ldr r4, [sp, #20]
        ldr r5, [sp, #24]
        ldr r6, [sp, #28]
        swi 0
        pop {r4-r7}
        bx lr
        .global trap
trap:   .word 0xE7F001F0
