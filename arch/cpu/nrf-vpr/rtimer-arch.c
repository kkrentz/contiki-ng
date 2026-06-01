#include "contiki.h"
#include "sys/rtimer.h"
#include "rtimer-arch.h"
#include <stdint.h>

void
rtimer_arch_init(void)
{
}

void
rtimer_arch_schedule(rtimer_clock_t t)
{
  (void)t;
}

rtimer_clock_t
rtimer_arch_now(void)
{
  uint32_t lo;
  __asm__ volatile ("csrr %0, cycle" : "=r"(lo));
  return (rtimer_clock_t)lo;
}
