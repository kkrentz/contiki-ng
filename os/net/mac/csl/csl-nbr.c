/*
 * Copyright (c) 2018, Hasso-Plattner-Institut.
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
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \addtogroup csl
 * @{
 *
 * \file
 *         Stores CSL-specific metadata of L2-neighbors.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/csl/csl-nbr.h"
#include "net/mac/csl/csl.h"

#if AKES_MAC_ENABLED

static csl_nbr_tentative_t tentatives[AKES_NBR_MAX_TENTATIVES];
static csl_nbr_t nbrs[AKES_NBR_MAX];

/*---------------------------------------------------------------------------*/
csl_nbr_tentative_t *
csl_nbr_get_tentative(const akes_nbr_tentative_t *tentative)
{
  return &tentatives[akes_nbr_index_of_tentative(tentative)];
}
/*---------------------------------------------------------------------------*/
csl_nbr_t *
csl_nbr_get(const akes_nbr_t *nbr)
{
  return &nbrs[akes_nbr_index_of(nbr)];
}
/*---------------------------------------------------------------------------*/
csl_nbr_t *
csl_nbr_get_receiver(void)
{
  const akes_nbr_entry_t *entry = akes_nbr_get_receiver_entry();
  if(!entry) {
    return NULL;
  }

  const akes_nbr_t *akes_nbr;
#if !CSL_COMPLIANT
  akes_nbr = csl_state.transmit.subtype == CSL_SUBTYPE_HELLOACK
#else /* !CSL_COMPLIANT */
  akes_nbr = akes_mac_is_helloack()
#endif /* !CSL_COMPLIANT */
             ? entry->tentative
             : entry->permanent;
  if(!akes_nbr) {
    return NULL;
  }

  return csl_nbr_get(akes_nbr);
}
/*---------------------------------------------------------------------------*/
uint8_t
csl_nbr_get_index_of(csl_nbr_t *nbr)
{
  return nbr - nbrs;
}
/*---------------------------------------------------------------------------*/

#endif /* AKES_MAC_ENABLED */

/** @} */
