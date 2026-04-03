# Contiki-NG TrustZone example

This example contains two projects for the secure world and the normal
world. Each project is compiled and linked into a separate firmware
image, which are then merged into a single hex file for programming the
IoT device.

The only supported platform is the Nordic Semiconductor nRF5340. The
application processor runs the merged TrustZone firmware; the network
processor runs the IPC radio service which provides 802.15.4 radio
access. Radio operations from the normal world pass through the secure
world's NSC entry points, enabling communication policy enforcement at
the TrustZone boundary.

## Getting started

Run `make` to build the secure and normal world firmwares and merge
the hex files. The merged hex is placed in
`secure-world/build/nrf/nrf5340/dk/application/tz-merged.hex`.

The network core must also be flashed with the IPC radio service:

```sh
make -C ../ipc-radio-service TARGET=nrf BOARD=nrf5340/dk/network ipc-radio-service.upload
```

Then flash the merged TrustZone firmware:

```sh
make upload
```

A specific serial port can be chosen with `PORT=/dev/<port>`.

To see serial output:

```sh
make login PORT=/dev/<PORT>
```

## Using a different normal-world application

The default normal world is a minimal example. To run any Contiki-NG
application (e.g., RPL UDP) in the normal world, use the `normal-world/`
Makefile as a template. The key settings are:

- `TRUSTZONE_SECURE_BUILD = 0`
- `TRUSTZONE_SECURE_WORLD_PATH` pointing to the secure-world directory

For example, to build RPL UDP as the normal world:

```sh
make -C examples/rpl-udp TARGET=nrf BOARD=nrf5340/dk/application \
     TRUSTZONE_SECURE_BUILD=0 \
     TRUSTZONE_SECURE_WORLD_PATH=../../examples/platform-specific/nrf/trustzone/secure-world \
     udp-server
```

The `tz_radio_driver` is selected automatically in the normal-world
build. Then merge with the secure world:

```sh
make -C examples/platform-specific/nrf/trustzone/secure-world

srec_cat \
  examples/platform-specific/nrf/trustzone/secure-world/build/nrf/nrf5340/dk/application/secure-world-example.hex -Intel \
  examples/rpl-udp/build/nrf/nrf5340/dk/application/udp-server.hex -Intel \
  -o merged.hex -Intel
```

Flash the network core and `merged.hex` to the application core.

## GDB setup for nRF (Linux)

Install the prerequisites for GDB if not already installed. For example,
you need nRF Command Line (nrfjprog), SEGGER J-Link,
GNU Arm Embedded toolchain, etc. These can be installed by following the
instructions in [contiki-nrf](https://docs.contiki-ng.org/en/develop/doc/platforms/nrf.html#prerequisites-and-setup).

1. Install gdb-multiarch (should already be installed with the GNU Arm embedded toolchain)
    ```sh
    sudo apt-get update -y
    sudo apt-get install gdb-multiarch
    ```
2. Compile the firmwares with debug option flags (e.g., `-O0 -ggdb2 -g2`)
to create debug symbols.

3. Open a JLinkGDBServer to allow connections from the GDB client (In
this case we target the nRF5340).
    ```sh
    JLinkGDBServer -device nrf5340_xxaa -if swd -port 2331
    ```
    * `-device` nrfxx_xxaa (What type of nrf device)
    * `-if` specifies the debug interface
    * `-port` which port to use

4. In another terminal, start gdb-multiarch:
    ```sh
    gdb-multiarch example.FILE
    ```
    * `file` could for example be .ELF or .out etc.

5. In GDB, connect to the GDB server:
    ```sh
    target remote localhost:2331
    ```

It can be good to turn off the uarte_write loop, so it is possible to
read other things.
