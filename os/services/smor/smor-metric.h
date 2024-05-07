/*
 * Copyright (c) 2023, Uppsala universitet.
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

/**
 * \file
 *         Interface to the routing metric.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef SMOR_METRIC_H_
#define SMOR_METRIC_H_

#include "net/link-stats.h"
#include "net/linkaddr.h"
#include <stdbool.h>

#define SMOR_METRIC smor_etx_metric
#define SMOR_METRIC_LEN (sizeof(smor_metric_t))

typedef link_packet_stat_t smor_metric_t;

struct smor_metric {
  void (* init)(void);
  smor_metric_t (* get_max)(void);
  smor_metric_t (* get_min)(void);
  smor_metric_t (* judge_link_to)(const linkaddr_t *addr);
  smor_metric_t (* judge_path)(smor_metric_t first_hop_metric,
      smor_metric_t second_hop_metric);
  bool (* better_than)(smor_metric_t this_metric,
      smor_metric_t that_metric);
};

extern const struct smor_metric SMOR_METRIC;

#endif /* SMOR_METRIC_H_ */
