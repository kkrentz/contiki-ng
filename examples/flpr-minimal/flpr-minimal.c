/* Smallest possible FLPR test: write a magic value to the shared counter,
 * then increment it in a busy loop. If M33 sees anything other than 0,
 * FLPR is executing from the address we set in INITPC.                */

#include <stdint.h>

#define COUNTER (*(volatile uint32_t *)0x2003F000UL)

int
main(void)
{
  /* First write — proves we reached main(). */
  COUNTER = 0xDEADBEEFUL;

  /* Then count up forever — proves we keep running. */
  uint32_t n = 1;
  for(;;) {
    COUNTER = n++;
    /* small busy delay so M33's 1 Hz poll catches different values. */
    for(volatile int i = 0; i < 1000000; i++) { }
  }
}
