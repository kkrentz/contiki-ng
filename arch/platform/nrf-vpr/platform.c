#include "contiki.h"
#include "sys/process.h"
#include "sys/etimer.h"
#include "sys/clock.h"
#include "sys/int-master.h"

void
platform_init_stage_one(void)
{
}

void
platform_init_stage_two(void)
{
}

void
platform_init_stage_three(void)
{
}

void
platform_main_loop(void)
{
  while(1) {
    process_run();
    etimer_request_poll();
  }
}

void
platform_idle(void)
{
}
