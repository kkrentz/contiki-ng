#include "contiki-net.h"
#include "sys/cc.h"
#include "sys/rtimer.h"
#include <string.h>

#include "sys/log.h"
#define LOG_MODULE "drizzle"
#define LOG_LEVEL LOG_LEVEL_DBG

#define DROPLET_LEN (RADIO_SHR_LEN + RADIO_HEADER_LEN)
#define MIN_PREPARE_LEAD_OVER_LOOP (10)

PROCESS(drizzle_process, "drizzle_process");
AUTOSTART_PROCESSES(&drizzle_process);

/*---------------------------------------------------------------------------*/
static void
on_timeout(struct rtimer *rt, void *ptr)
{
  process_post_synch(&drizzle_process, PROCESS_EVENT_CONTINUE, NULL);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(drizzle_process, ev, data)
{
  static uint_fast32_t drizzle_pos;
  static uint8_t droplets[RADIO_MAX_SEQUENCE_LEN];
  static rtimer_clock_t drizzle_start;
  static struct rtimer timer;

  PROCESS_BEGIN();

  if (NETSTACK_RADIO.async_enter()) {
    LOG_ERR("async_enter failed\n");
    PROCESS_EXIT();
  }

  for(;
      drizzle_pos <= (RADIO_MAX_SEQUENCE_LEN - DROPLET_LEN);
      drizzle_pos += DROPLET_LEN) {
    memcpy(droplets + drizzle_pos, radio_shr, RADIO_SHR_LEN);
    droplets[drizzle_pos + RADIO_SHR_LEN] = RADIO_MAX_PAYLOAD;
  }

  if(NETSTACK_RADIO.async_prepare_sequence(droplets, drizzle_pos)) {
    LOG_ERR("async_prepare_sequence failed\n");
    PROCESS_EXIT();
  }

  drizzle_start = RTIMER_NOW() + RADIO_TRANSMIT_CALIBRATION_TIME;
  if(NETSTACK_RADIO.async_transmit_sequence()) {
    LOG_ERR("async_transmit_sequence failed\n");
    PROCESS_EXIT();
  }

  while(1) {
    rtimer_clock_t next_append = drizzle_start
        + RADIO_TIME_TO_TRANSMIT(RADIO_SYMBOLS_PER_BYTE
            * (drizzle_pos - (MIN_PREPARE_LEAD_OVER_LOOP / 2)));
    if(rtimer_set(&timer, next_append, 1, on_timeout, NULL) != RTIMER_OK) {
      LOG_ERR("rtimer_set failed\n");
      break;
    }
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_CONTINUE);
    uint_fast16_t appendix_len = DROPLET_LEN
        * ((RADIO_MAX_SEQUENCE_LEN - MIN_PREPARE_LEAD_OVER_LOOP) / DROPLET_LEN);
    drizzle_pos += appendix_len;
    if(NETSTACK_RADIO.async_append_to_sequence(droplets, appendix_len)) {
      LOG_ERR("async_append_to_sequence failed\n");
      break;
    }
  }
  NETSTACK_RADIO.async_off();

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
