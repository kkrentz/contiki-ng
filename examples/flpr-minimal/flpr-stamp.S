/* 5-instruction proof-of-life: write 0xCAFEBABE to 0x2003F000 and spin. */
        .section .startup, "ax"
        .global Reset_Handler
Reset_Handler:
        li      t0, 0x2003F000          /* t0 = counter address         */
        lui     t1, 0xCAFEC             /* t1 = 0xCAFEC000              */
        addi    t1, t1, -0x542          /* t1 = 0xCAFEBABE              */
        sw      t1, 0(t0)               /* [0x2003F000] = 0xCAFEBABE    */
1:      j       1b
