#include "contiki.h"
#include "sys/clock.h"
#include <stdint.h>

#ifndef VPR_CYCLE_HZ
#define VPR_CYCLE_HZ 16000000UL
#endif

static uint64_t epoch_cycles;

static uint64_t
read_cycles(void)
{
  uint32_t lo1, hi, lo2;
  do {
    __asm__ volatile ("csrr %0, mcycleh" : "=r"(hi));
    __asm__ volatile ("csrr %0, mcycle"  : "=r"(lo1));
    __asm__ volatile ("csrr %0, mcycleh" : "=r"(lo2));
  } while(hi != lo2);
  return ((uint64_t)hi << 32) | lo1;
}

void
clock_init(void)
{
  epoch_cycles = read_cycles();
}

/* PoC: cycle/mcycle CSRs are 0 on the VPR. Advance time by one tick per
 * call — wrong rate, but proves the Contiki kernel + etimer + scheduler
 * are all wired correctly. Replace with VTIM-driven clock once running. */
static volatile clock_time_t fake_time = 0;
clock_time_t
clock_time(void)
{
  return ++fake_time;
}

unsigned long
clock_seconds(void)
{
  return (unsigned long)((read_cycles() - epoch_cycles) / VPR_CYCLE_HZ);
}

void
clock_wait(clock_time_t t)
{
  clock_time_t end = clock_time() + t;
  while(clock_time() < end) { }
}

void
clock_delay_usec(uint16_t us)
{
  uint64_t end = read_cycles() + ((uint64_t)us * VPR_CYCLE_HZ) / 1000000UL;
  while(read_cycles() < end) { }
}

void
clock_delay(unsigned int us)
{
  clock_delay_usec((uint16_t)us);
}
