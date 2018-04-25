/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
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
 */

#include <stdio.h>
#include <string.h>
#include "coap-engine.h"
#include "coap.h"
#include "lib/sensors.h"
#include "dev/sht21.h"
#include "dev/max44009.h"

static void res_get_handler(coap_message_t *request,
    coap_message_t *response,
    uint8_t *buffer,
    uint16_t preferred_size,
    int32_t *offset);
static void res_event_handler(void);

EVENT_RESOURCE(res_sensors,
    "title=\"res_sensors\";obs",
    res_get_handler,
    NULL,
    NULL,
    NULL,
    res_event_handler);

/*---------------------------------------------------------------------------*/
static void
res_get_handler(coap_message_t *request,
    coap_message_t *response,
    uint8_t *buffer,
    uint16_t preferred_size,
    int32_t *offset)
{
  int temperature;
  int humidity;
  int light;
  int length;

  temperature = sht21.value(SHT21_READ_TEMP);
  humidity = sht21.value(SHT21_READ_RHUM);
  light = max44009.value(MAX44009_READ_LIGHT);

  coap_set_header_content_format(response, TEXT_PLAIN);
  length = snprintf((char *)buffer,
      preferred_size,
      "%i;%i;%i", temperature, humidity, light);
  coap_set_payload(response, buffer, length);
}
/*---------------------------------------------------------------------------*/
static void
res_event_handler(void)
{
  coap_notify_observers(&res_sensors);
}
/*---------------------------------------------------------------------------*/
