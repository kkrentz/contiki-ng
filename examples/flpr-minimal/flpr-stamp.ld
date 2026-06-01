/* Minimal linker: place .startup at 0x20028000 (the FLPR exec memory). */
OUTPUT_FORMAT("elf32-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(Reset_Handler)

MEMORY {
    FLASH (rx) : ORIGIN = 0x20028000, LENGTH = 0x1000
}

SECTIONS {
    .startup : { *(.startup) } > FLASH
}
