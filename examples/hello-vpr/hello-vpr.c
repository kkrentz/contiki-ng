#include "contiki.h"
#include "sys/etimer.h"
#include "nrf.h"
#include <stdint.h>

/* Shared counter location for M33 polling. */
#define SHARED_COUNTER  (*(volatile uint32_t *)0x2003F000UL)

/* LED0 on nRF54L15-DK = gpio2 pin 9, active high. */
#define LED0_PIN        9
#define LED0_BIT        (1u << LED0_PIN)

PROCESS(hello_vpr_process, "hello-vpr");
AUTOSTART_PROCESSES(&hello_vpr_process);

PROCESS_THREAD(hello_vpr_process, ev, data)
{
  static struct etimer et;
  static uint32_t tick;

  PROCESS_BEGIN();

  /* Configure LED0 as output. M33 may have already done this, but it's
   * idempotent — DIRSET is a write-1-to-set register. */
  NRF_P2_S->DIRSET = LED0_BIT;

  while(1) {
    SHARED_COUNTER = tick;
    if(tick & 1) {
      NRF_P2_S->OUTSET = LED0_BIT;
    } else {
      NRF_P2_S->OUTCLR = LED0_BIT;
    }
    etimer_set(&et, CLOCK_SECOND / 2);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    tick++;
  }

  PROCESS_END();
}
