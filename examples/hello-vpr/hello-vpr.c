#include "contiki.h"
#include "sys/etimer.h"
#include <stdint.h>

/* Shared counter location agreed with M33 firmware. Top of FLPR RAM.
 * M33 reads its mirror of this physical address via the chip's global map. */
#define SHARED_COUNTER (*(volatile uint32_t *)0x2003F000UL)

PROCESS(hello_vpr_process, "hello-vpr");
AUTOSTART_PROCESSES(&hello_vpr_process);

PROCESS_THREAD(hello_vpr_process, ev, data)
{
  static struct etimer et;
  static uint32_t tick;

  PROCESS_BEGIN();

  while(1) {
    /* Visible to M33 while we yield in PROCESS_WAIT (99% of the time). */
    SHARED_COUNTER = tick;
    etimer_set(&et, CLOCK_SECOND / 2);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    tick++;
  }

  PROCESS_END();
}
