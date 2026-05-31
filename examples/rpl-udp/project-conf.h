/*
 * Project configuration for the rpl-udp example.
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_
/*---------------------------------------------------------------------------*/
/*
 * On the nRF5340 application core paired with an nrf_802154 network-core
 * radio service, the radio (running on the net core) acknowledges received
 * frames in hardware and reports the transmit verdict over IPC. CSMA should
 * therefore trust RADIO_TX_OK/RADIO_TX_NOACK from transmit() rather than
 * polling for ACK frames, which the hardware-ACK net core never forwards.
 *
 * NOTE: only correct when the net core is built with NRF_802154=1. With the
 * legacy raw radio service, leave CSMA_USE_RADIO_ACK at its default (0).
 */
#if defined(CONTIKI_BOARD_NRF5340_DK_APPLICATION)
#define CSMA_CONF_USE_RADIO_ACK 1
#endif
/*---------------------------------------------------------------------------*/
#endif /* PROJECT_CONF_H_ */
