#include "contiki-net.h"

PROCESS(leaf_process, "leaf_process");
AUTOSTART_PROCESSES(&leaf_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(leaf_process, ev, data)
{
  PROCESS_BEGIN();

  NETSTACK_MAC.on();

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
