/* FLPR firmware linker script using Nordic's canonical FLPR SRAM partition.
 * Per Zephyr DTS (nrf54l15_cpuflpr.dtsi): FLPR's SRAM block is at M33-view
 * 0x20028000..0x20040000 (96 KB). The Zephyr vpr_launcher writes INITPC to
 * the parent (M33-bus) address of execution-memory, i.e. 0x20028000.       */

SEARCH_DIR(.)
GROUP(-lgcc)

MEMORY
{
  FLASH (rx) : ORIGIN = 0x20028000, LENGTH = 0x8000   /* 32 KB code/.rodata */
  RAM (rwx)  : ORIGIN = 0x20030000, LENGTH = 0xF000   /* 60 KB data/.bss/stack */
}

INCLUDE "nrf_common_riscv.ld"
