#include "contiki-net.h"

PROCESS(root_process, "root_process");
AUTOSTART_PROCESSES(&root_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(root_process, ev, data)
{
  PROCESS_BEGIN();

  NETSTACK_ROUTING.root_start();
  NETSTACK_MAC.on();

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
