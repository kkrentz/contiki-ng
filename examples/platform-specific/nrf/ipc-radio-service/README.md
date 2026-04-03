# IPC Radio Service

Radio service firmware for the nRF5340 **network core**. Provides
802.15.4 radio access to the application core via IPC shared memory.

This is a minimal Contiki-NG image whose sole purpose is to receive
commands from the application core, call the nRF 802.15.4 radio
driver, and return results.

## Building and Flashing

The network core must be flashed **before** the application core:

```bash
make -C examples/platform-specific/nrf/ipc-radio-service \
     TARGET=nrf BOARD=nrf5340/dk/network
make -C examples/platform-specific/nrf/ipc-radio-service \
     TARGET=nrf BOARD=nrf5340/dk/network ipc-radio-service.upload
```

## Design

Frame reception is fully interrupt-driven via the IPC MAC driver:
the radio ISR triggers the radio driver process, which calls the
IPC MAC's input function to forward the frame to the app core via
shared memory. Between events, the CPU sleeps (WFI), minimizing
energy consumption and preventing bus stalls.

IPC commands from the app core are delivered via IPC interrupt.
The service process wakes only when there is actual work to do.

UARTE is disabled on the network core (`NRF_HAS_UARTE 0`). All
debug output is redirected to a shared memory ring buffer, which
the application core drains and prints with a `[NET]` prefix.

TSCH is not supported — the IPC latency is too high for TSCH slot
timing. Use CSMA (the default).

## Running RPL UDP over IPC

First, flash the network core radio service (see above). Then flash
the RPL UDP server on the application core:

```bash
make -C examples/rpl-udp TARGET=nrf BOARD=nrf5340/dk/application \
     DEFINES=NETSTACK_CONF_RADIO=ipc_radio_driver udp-server.upload
```

On a second node (e.g., nRF52840 DK), flash the RPL UDP client:

```bash
make -C examples/rpl-udp TARGET=nrf BOARD=nrf52840/dk udp-client.upload
```

### TrustZone Mode

To run with the radio driver in the TrustZone secure world:

1. Build the secure world:

```bash
make -C examples/platform-specific/nrf/trustzone/secure-world
```

2. Build the normal-world RPL UDP server:

```bash
make -C examples/rpl-udp TARGET=nrf BOARD=nrf5340/dk/application \
     TRUSTZONE_SECURE_BUILD=0 \
     TRUSTZONE_SECURE_WORLD_PATH=../../examples/platform-specific/nrf/trustzone/secure-world \
     udp-server
```

3. Merge the secure and normal world hex files and flash to the
   application core:

```bash
srec_cat \
  examples/platform-specific/nrf/trustzone/secure-world/build/nrf/nrf5340/dk/application/secure-world-example.hex -Intel \
  examples/rpl-udp/build/nrf/nrf5340/dk/application/udp-server.hex -Intel \
  -o merged.hex -Intel
```

## Related

- `arch/cpu/nrf/net/README.md` — Full IPC architecture documentation
- `arch/cpu/nrf/net/nrf-ipc.h` — IPC protocol definitions
- `arch/cpu/nrf/net/nrf-ipc-mac.c` — IPC MAC driver (net core)
