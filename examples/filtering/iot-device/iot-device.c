/*
 * Copyright (c) 2021, Uppsala universitet.
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

/**
 * \file
 *         Demonstrates the usage of the filtering client.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "filtering-client.h"
#include "net/linkaddr.h"
#include <coap3/coap.h>

#include "sys/log.h"
#define LOG_MODULE "IoT-device"
#define LOG_LEVEL LOG_LEVEL_INFO

static void on_registered(coap_context_t *context);
static void hello(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response);

PROCESS(iot_device_process, "IoT device process");
AUTOSTART_PROCESSES(&iot_device_process);
static filtering_client_subscription_t observer = { NULL , on_registered };

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(iot_device_process, ev, data)
{
  PROCESS_BEGIN();

  filtering_client_start();
  filtering_client_subscribe(&observer);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static void
on_registered(coap_context_t *context)
{
  coap_str_const_t *ruri = coap_make_str_const("hello");
  coap_resource_t *resource =
      coap_resource_init(ruri, COAP_RESOURCE_FLAGS_OSCORE_NG_ONLY);
  if (!resource) {
    LOG_ERR("coap_resource_init failed\n");
    return;
  }
  coap_register_handler(resource, COAP_REQUEST_GET, hello);
  coap_add_resource(context, resource);
}
/*---------------------------------------------------------------------------*/
static void
hello(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response)
{
  filtering_client_prolong();
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_add_data(response, 5, (const uint8_t *)"world");
}
/*---------------------------------------------------------------------------*/
