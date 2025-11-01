/*
 * Copyright (c) 2017, RISE SICS
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "net/linkaddr.h"
#include "smor/smor-db.h"
#include <stdio.h>
#include <string.h>

/*---------------------------------------------------------------------------*/
static const char *TOP = "<html>\n  <head>\n    <title>Contiki-NG</title>\n  </head>\n<body>\n";
static const char *BOTTOM = "</body>\n</html>\n";
static char buf[256];
static int blen;
#define ADD(...) do {                                                   \
    blen += snprintf(&buf[blen], sizeof(buf) - blen, __VA_ARGS__);      \
  } while(0)
#define SEND(s) do { \
  SEND_STRING(s, buf); \
  blen = 0; \
} while(0);

/* Use simple webserver with only one page for minimum footprint.
 * Multiple connections can result in interleaved tcp segments since
 * a single static buffer is used for all segments.
 */
#include "httpd-simple.h"

/*---------------------------------------------------------------------------*/
static void
add_linkaddr(const linkaddr_t *linkaddr)
{
  for(size_t i = 0; i < LINKADDR_SIZE; i++) {
    ADD("%x", linkaddr->u8[i]);
  }
}
/*---------------------------------------------------------------------------*/
static
PT_THREAD(generate_routes(struct httpd_state *s))
{
  static smor_db_id_t i;
  static smor_db_id_t j;

  PSOCK_BEGIN(&s->sout);
  SEND_STRING(&s->sout, TOP);

  ADD("  Neighbors\n  <ul>\n");
  SEND(&s->sout);
  for(i = 0; i < smor_db_my_id; i++) {
    if(smor_db_have_link(smor_db_my_id, i)) {
      ADD("    <li>");
      add_linkaddr(smor_db_get_address(i));
      ADD("</li>\n");
      SEND(&s->sout);
    }
  }
  ADD("  </ul>\n");
  SEND(&s->sout);

  ADD("  Routes\n  <ul>\n");
  SEND(&s->sout);
  for(i = 0; i < smor_db_my_id; i++) {
    if(smor_db_have_link(smor_db_my_id, i)) {
      for(j = 0; j < smor_db_my_id; j++) {
        if((i != j) && smor_db_have_link(j, i)) {
          ADD("    <li>");
          add_linkaddr(smor_db_get_address(j));
          ADD(" via ");
          add_linkaddr(smor_db_get_address(i));
          ADD("</li>\n");
          SEND(&s->sout);
        }
      }
    }
  }
  ADD("  </ul>\n");
  SEND(&s->sout);

  SEND_STRING(&s->sout, BOTTOM);

  PSOCK_END(&s->sout);
}
/*---------------------------------------------------------------------------*/
PROCESS(webserver_nogui_process, "Web server");
PROCESS_THREAD(webserver_nogui_process, ev, data)
{
  PROCESS_BEGIN();

  httpd_init();

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(ev == tcpip_event);
    httpd_appcall(data);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
httpd_simple_script_t
httpd_simple_get_script(const char *name)
{
  return generate_routes;
}
/*---------------------------------------------------------------------------*/
