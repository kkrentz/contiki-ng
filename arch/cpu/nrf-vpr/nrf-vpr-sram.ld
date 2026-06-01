/* Link the FLPR firmware to run from a fixed SRAM region the M33 will fill.
 * FLPR's view: code at 0x20030000, data immediately after. Shared counter
 * lives at 0x2003F000 in both M33 and FLPR views.                       */

SEARCH_DIR(.)
GROUP(-lgcc)

MEMORY
{
  FLASH (rx) : ORIGIN = 0x20030000, LENGTH = 0x8000  /* 32 KB code/.rodata */
  RAM (rwx)  : ORIGIN = 0x20038000, LENGTH = 0x6000  /* 24 KB data/.bss/stack */
}

INCLUDE "nrf_common_riscv.ld"
