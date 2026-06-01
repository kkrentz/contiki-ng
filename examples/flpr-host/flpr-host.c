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

/* Try both views and report what each one shows us. */
#define VPR_NS ((volatile NRF_VPR_Type *)0x4004C000UL)
#define VPR_S  ((volatile NRF_VPR_Type *)0x5004C000UL)

static volatile uint32_t s_initpc_before, s_cpurun_before;
static volatile uint32_t s_initpc_after,  s_cpurun_after;
static volatile uint32_t ns_initpc_before, ns_cpurun_before;
static volatile uint32_t ns_initpc_after,  ns_cpurun_after;

static void
flpr_diag_and_start(void)
{
  /* 1. Copy the embedded FLPR binary into SRAM at the link address. */
  memcpy((void *)FLPR_BLOB_LOAD_ADDR, flpr_blob, flpr_blob_len);

  /* 2. NS readback BEFORE any writes. */
  ns_initpc_before = VPR_NS->INITPC;
  ns_cpurun_before = VPR_NS->CPURUN;

  /* 3. Write via NS view. */
  VPR_NS->INITPC = FLPR_BLOB_ENTRY_PC;
  VPR_NS->CPURUN = 1u;

  /* 4. NS readback AFTER writes. */
  ns_initpc_after = VPR_NS->INITPC;
  ns_cpurun_after = VPR_NS->CPURUN;
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
  flpr_diag_and_start();

  LOG_INFO("NS VPR before: INITPC=0x%08lx CPURUN=0x%lx\n",
           (unsigned long)ns_initpc_before, (unsigned long)ns_cpurun_before);
  LOG_INFO("NS VPR after : INITPC=0x%08lx CPURUN=0x%lx\n",
           (unsigned long)ns_initpc_after, (unsigned long)ns_cpurun_after);

  if(ns_initpc_after == FLPR_BLOB_ENTRY_PC && ns_cpurun_after == 1) {
    LOG_INFO("Writes were ACCEPTED via NS view (SPU not blocking).\n");
  } else if(ns_initpc_after == 0 && ns_cpurun_after == 0) {
    LOG_INFO("Writes were DROPPED via NS view (SPU is blocking).\n");
  } else {
    LOG_INFO("Mixed: NS view partially accepted writes.\n");
  }

  etimer_set(&et, CLOCK_SECOND);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    uint32_t now = FLPR_SHARED_COUNTER;
    if(now != last_tick) {
      LOG_INFO("[FLPR] tick %u (delta %d)\n",
               (unsigned)now, (int)(now - last_tick));
      last_tick = now;
    } else {
      LOG_INFO("[FLPR] counter unchanged at %u, CPURUN=0x%lx\n",
               (unsigned)now, (unsigned long)VPR_NS->CPURUN);
    }
    etimer_reset(&et);
  }

  PROCESS_END();
}
