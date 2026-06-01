#include "contiki.h"
#include "sys/log.h"
#include "sys/etimer.h"
#include "nrf.h"
#include "hal/nrf_vpr.h"

#include "flpr-blob.h"

#include <stdint.h>
#include <string.h>

#define LOG_MODULE "flpr-host"
#define LOG_LEVEL  LOG_LEVEL_INFO

static void
flpr_load_and_start(void)
{
  /* 1. Copy the embedded FLPR binary into SRAM at the link address. */
  memcpy((void *)FLPR_BLOB_LOAD_ADDR, flpr_blob, flpr_blob_len);

  /* 2. Tell the VPR where to start and release it from reset. */
  nrf_vpr_initpc_set(NRF_VPR00_NS, FLPR_BLOB_ENTRY_PC);
  nrf_vpr_cpurun_set(NRF_VPR00_NS, true);
}

PROCESS(flpr_host_process, "flpr-host");
AUTOSTART_PROCESSES(&flpr_host_process);

PROCESS_THREAD(flpr_host_process, ev, data)
{
  static struct etimer et;
  static uint32_t last_tick;

  PROCESS_BEGIN();

  LOG_INFO("M33 boot complete, blob=%u bytes, loading FLPR...\n",
           (unsigned)flpr_blob_len);

  FLPR_SHARED_COUNTER = 0;
  flpr_load_and_start();

  LOG_INFO("FLPR released; polling shared counter @ 0x2003F000\n");

  etimer_set(&et, CLOCK_SECOND);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    uint32_t now = FLPR_SHARED_COUNTER;
    if(now != last_tick) {
      LOG_INFO("[FLPR] tick %u (delta %d)\n",
               (unsigned)now, (int)(now - last_tick));
      last_tick = now;
    } else {
      LOG_INFO("[FLPR] counter unchanged at %u\n", (unsigned)now);
    }
    etimer_reset(&et);
  }

  PROCESS_END();
}
