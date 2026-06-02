/* M33-side FLPR launcher — replicates Zephyr's nordic_vpr_launcher
 * boot dance exactly:
 *   1. memcpy blob to execution memory
 *   2. (if enable-secure DT prop) nrf_spu_periph_perm_secattr_set(SECATTR=Secure)
 *   3. nrf_vpr_initpc_set(exec_addr)
 *   4. nrf_vpr_cpurun_set(true)
 * Per nrf54l_05_10_15_cpuapp.dtsi the VPR has enable-secure;, so we MUST
 * do step 2 from the Secure address.
 */

#include "contiki.h"
#include "sys/log.h"
#include "sys/etimer.h"
#include "nrf.h"

#include "flpr-blob.h"

#include <stdint.h>
#include <string.h>

#define LOG_MODULE "flpr-host"
#define LOG_LEVEL  LOG_LEVEL_INFO

/* Direct register access — bypass the HAL so we know exactly what we're doing. */

#define VPR_S    ((volatile struct { uint8_t pad[0x800]; uint32_t CPURUN; uint32_t rsv; uint32_t INITPC; } *)0x5004C000UL)
#define VPR_NS   ((volatile struct { uint8_t pad[0x800]; uint32_t CPURUN; uint32_t rsv; uint32_t INITPC; } *)0x4004C000UL)

/* SPU00 PERIPH[N].PERM @ NRF_SPU00_S_BASE + 0x500 + N*4
 * VPR00 slave index = (0x4004C000 >> 12) & 0x3F = 0xC (12) */
#define SPU00_S_PERIPH_VPR00_PERM   (*(volatile uint32_t *)(0x50040000UL + 0x500UL + 12UL*4))
#define SPU00_NS_PERIPH_VPR00_PERM  (*(volatile uint32_t *)(0x40040000UL + 0x500UL + 12UL*4))

#define PERM_SECATTR_BIT   (1u << 4)

PROCESS(flpr_host_process, "flpr-host");
AUTOSTART_PROCESSES(&flpr_host_process);

PROCESS_THREAD(flpr_host_process, ev, data)
{
  static struct etimer et;
  static uint32_t last_tick;

  PROCESS_BEGIN();

  LOG_INFO("M33 boot complete, blob=%u bytes\n", (unsigned)flpr_blob_len);

  /* Step 1: copy blob into FLPR execution memory. */
  memcpy((void *)FLPR_BLOB_LOAD_ADDR, flpr_blob, flpr_blob_len);
  LOG_INFO("Blob memcpy'd to 0x%08lx\n", (unsigned long)FLPR_BLOB_LOAD_ADDR);

  /* Step 2: ensure VPR is marked Secure in SPU (Zephyr's enable_secure path).
   * If our M33 is in NS, this will HardFault. If it succeeds, we're in S. */
  FLPR_SHARED_COUNTER = 0;

  uint32_t spu_perm_before;
  uint32_t spu_perm_after;
  uint32_t mode_marker;

  /* Try Secure SPU access. */
  __asm__ volatile ("" ::: "memory");
  spu_perm_before = SPU00_S_PERIPH_VPR00_PERM;
  SPU00_S_PERIPH_VPR00_PERM = spu_perm_before | PERM_SECATTR_BIT;
  spu_perm_after = SPU00_S_PERIPH_VPR00_PERM;
  mode_marker = 0xDEADC0DE;   /* if we got here, S mode works */

  LOG_INFO("SPU PERIPH[12] before=0x%08lx after=0x%08lx\n",
           (unsigned long)spu_perm_before, (unsigned long)spu_perm_after);
  LOG_INFO("M33 is in SECURE mode (SPU S access succeeded). marker=0x%08lx\n",
           (unsigned long)mode_marker);

  /* Step 3+4: set INITPC and CPURUN via the SAME view (S, matching our access). */
  VPR_S->INITPC = FLPR_BLOB_ENTRY_PC;
  VPR_S->CPURUN = 1u;

  LOG_INFO("VPR_S after launch: INITPC=0x%08lx CPURUN=0x%lx\n",
           (unsigned long)VPR_S->INITPC, (unsigned long)VPR_S->CPURUN);

  etimer_set(&et, CLOCK_SECOND);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    uint32_t now = FLPR_SHARED_COUNTER;
    if(now != last_tick) {
      LOG_INFO("[FLPR] tick %u\n", (unsigned)now);
      last_tick = now;
    } else {
      uint32_t mepc = *(volatile uint32_t *)0x2003F004UL;
      LOG_INFO("[FLPR] counter 0x%08lx mepc=0x%08lx CPURUN=0x%lx\n",
               (unsigned long)now, (unsigned long)mepc, (unsigned long)VPR_S->CPURUN);
    }
    etimer_reset(&et);
  }

  PROCESS_END();
}
