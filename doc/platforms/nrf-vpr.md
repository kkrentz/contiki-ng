# nrf-vpr: Nordic Semiconductor nRF54L15 FLPR (RV32E coprocessor)

This guide describes the Contiki-NG port for the **FLPR** (Fast Lightweight Peripheral Processor) — the RISC-V VPR coprocessor on the nRF54L15. The FLPR is an RV32E core (16 GP registers, no F/D extensions) with its own tightly-coupled SRAM/RRAM partitions. It does not run by itself; the Cortex-M33 application core loads its firmware into SRAM and releases it from reset at run time.

Hardware-validated on the nRF54L15-DK (PCA10156).

## Port Features

The following features are implemented:

* Contiki-NG process scheduler, etimer, ctimer running on the FLPR
* `clock_time()` driven by GRTC SYSCOUNTER — 1 ms resolution at real wall-clock rate
* GPIO write access from the FLPR (LED demo: gpio2 pin 9 toggles at 1 Hz)
* M33-side companion app that embeds the FLPR blob, performs the SPU + VPR boot dance, polls a shared counter, and blinks a second LED
* Resulting FLPR firmware is ~8 KB (kernel + one process)

Not yet implemented:

* Interrupt-driven etimer compare (GRTC CC channel 3) — currently polled in the main loop
* rtimer (GRTC CC channel 4 reserved for it)
* 802.15.4 radio on the FLPR — on this port the radio remains on the M33

## Prerequisites and Setup

Two toolchains are needed because the M33 and FLPR sides build separately and the M33 image embeds the FLPR binary.

### M33 side

Same as the existing `nrf` port:

* `arm-none-eabi-gcc` (Homebrew `gcc-arm-embedded` or system package)
* `gmake` (GNU Make 4+ — Apple's bundled make 3.81 is too old)
* OpenOCD with nRF54L15 support, or J-Link tools

### FLPR side

* Zephyr SDK RISC-V toolchain (`riscv64-zephyr-elf-gcc 14.3+` — includes the RV32E multilib):

      ZSDK_VER=v1.0.1
      curl -L -o /tmp/zsdk-riscv.tar.xz \
          https://github.com/zephyrproject-rtos/sdk-ng/releases/download/$ZSDK_VER/toolchain_gnu_macos-aarch64_riscv64-zephyr-elf.tar.xz
      mkdir -p ~/zephyr-toolchain-riscv
      tar -xJf /tmp/zsdk-riscv.tar.xz -C ~/zephyr-toolchain-riscv --strip-components=1

  The FLPR build looks for it at `~/zephyr-toolchain-riscv` by default; override with `ZSDK_RISCV=...`.

* Python 3 for the blob-embedding script (`tools/flpr-blob-gen.py`).

## Getting Started

Shortest path to a running demo on the nRF54L15-DK:

    # 1. Build the FLPR firmware
    cd examples/hello-vpr
    gmake TARGET=nrf-vpr WERROR=0

    # 2. Embed the FLPR blob in a header that the M33 image includes
    cd ../flpr-host
    python3 ../../tools/flpr-blob-gen.py ../hello-vpr/build/nrf-vpr/hello-vpr.bin > flpr-blob.h

    # 3. Build + flash the M33 image
    gmake TARGET=nrf BOARD=nrf54l15/dk WERROR=0 flpr-host.flash

You should see:

* **LED0** (green, gpio2.9) blinking at **1 Hz** — driven by the FLPR
* **LED1** (green, gpio1.10) blinking at **2 Hz** — driven by the M33
* On the serial console (`make ... PORT=/dev/cu.usbmodem* login`):

      [INFO: flpr-host ] M33 boot complete, blob=8252 bytes
      [INFO: flpr-host ] Blob memcpy'd to 0x20028000
      [INFO: flpr-host ] SPU PERIPH[12] before=0x8001000a after=0x8001001a
      [INFO: flpr-host ] M33 is in SECURE mode (SPU S access succeeded)
      [INFO: flpr-host ] VPR_S after launch: INITPC=0x20028000 CPURUN=0x1
      [INFO: flpr-host ] [FLPR] tick 2
      [INFO: flpr-host ] [FLPR] tick 4
      ...

`tick` advances by exactly 2 per second, confirming the GRTC-driven Contiki kernel is running on the FLPR at real wall-clock rate.

## Examples

| Example                    | Target              | Purpose                                                                                                                                                             |
| -------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `examples/hello-vpr`       | `nrf-vpr`           | Smallest possible Contiki-NG running on the FLPR: one process, etimer, LED blink, tick counter in shared SRAM. Build output is the FLPR firmware blob.              |
| `examples/flpr-host`       | `nrf` (`nrf54l15/dk`) | M33-side companion. Embeds the FLPR blob, runs the SPU + VPR boot dance, polls the shared counter, blinks a second LED, prints over UART.                           |
| `examples/flpr-minimal`    | `nrf-vpr`           | Five-instruction RV32E "stamp" probe (writes `0xCAFEBABE` to the shared counter and spins). Useful when porting to a new board to confirm the boot dance works.     |

## Compilation Targets

The FLPR side uses TARGET `nrf-vpr`. There is no BOARD selector — the only nRF54L15 board family supported today is the DK; pin-level differences live in the M33-side board config.

    # FLPR firmware
    gmake TARGET=nrf-vpr WERROR=0

    # M33 firmware (uses existing nrf port)
    gmake TARGET=nrf BOARD=nrf54l15/dk WERROR=0 <project>.flash
    gmake TARGET=nrf BOARD=nrf54l15/dk WERROR=0 PORT=/dev/cu.usbmodem* login

## Compilation Options

* `ZSDK_RISCV=<path>` — override the RISC-V toolchain location (default: `~/zephyr-toolchain-riscv`).
* `WERROR=0` — currently required for the M33 build because of an RWX-segment warning from nrfx's M33 linker script. The FLPR build sets `-Wl,--no-warn-rwx-segments` directly so `WERROR` does not need to be relaxed.

## How it boots

The M33 launches the FLPR with the same sequence used by Zephyr's `nordic_vpr_launcher` driver:

    /* 1. Copy the FLPR binary into its execution memory (start of the   */
    /*    96 KB SRAM block the FLPR owns, per Zephyr cpuflpr DTS). */
    memcpy((void *)0x20028000, flpr_blob, flpr_blob_len);

    /* 2. Set VPR00's SPU PERIPHACCESS.SECATTR=Secure.                  */
    /*    Without this, INITPC/CPURUN writes succeed and read back, but */
    /*    the VPR never actually fetches a single instruction.          */
    NRF_SPU00_S->PERIPH[12].PERM |= (1u << 4);

    /* 3. Tell the VPR where to start.                                  */
    NRF_VPR00_S->INITPC = 0x20028000;

    /* 4. Release the VPR from reset.                                   */
    NRF_VPR00_S->CPURUN = 1;

All four writes use Secure addresses. Contiki on the nRF54L15 M33 runs in Secure mode by default, so no TrustZone transition is required.

## Implementation notes

Things worth knowing before modifying this port.

### nrfx startup must clear BSS

`arch/cpu/nrf/lib/nrfx/mdk/gcc_startup_nrf54l15_flpr.S` only emits the `.bss` / `.sbss` / `.tbss` zero-init loops when `__STARTUP_CLEAR_BSS` is defined. Without it, Contiki globals (`process_list`, `timerlist`, ...) hold whatever garbage was in SRAM and the kernel hangs the first time it walks one of those lists. `arch/cpu/nrf-vpr/Makefile.nrf-vpr` defines this.

### GRTC must be read via the Secure address

The M33 keeps GRTC's SPU PERIPHACCESS set to Secure, so the NS aperture (`0x400E2000`) faults from the FLPR with `mcause=5` (load access fault). Use `NRF_GRTC_S` (`0x500E2000`). `arch/cpu/nrf-vpr/clock-arch.c` does.

### Channel allowlist override for nrfx-grtc

The stock `nrfx_config_nrf54l15_flpr.h` template hard-codes `NRFX_GRTC_CONFIG_ALLOWED_CC_CHANNELS_MASK = 0xF0` (channels 4..7). That collides with M33's owned 5 and 6, with the zero-latency channel 7, and it omits channel 3 entirely. The Nordic split for nRF54L15 is M33: 0,1,2,5,6 / FLPR: 3,4. `Makefile.nrf-vpr` overrides the mask to `0x18`.

### Radio is on the M33, not the FLPR

The nRF54L15 802.15.4 backend uses TIMER20 and TIMER10 (`nrf_802154_platform_sl_lptimer.c`, `nrf_802154_platform_timestamper.c`), not GRTC. So the M33 radio stack and the FLPR clock do not contest.

### Trap handler

The nrfx-provided `Trap_Handler` is a silent infinite loop. `arch/cpu/nrf-vpr/startup-stubs.c` reroutes `mtvec` to a handler that writes `0xFA1100 | mcause` to `0x2003F000` and `mepc` to `0x2003F004` before spinning, so any CPU exception is visible from the M33-side console instead of silently hanging the FLPR.

## Known limitations

* The FLPR-blob-in-M33-`.rodata` pattern means rebuilding the FLPR requires manually regenerating `examples/flpr-host/flpr-blob.h`. A Makefile rule that does this automatically is on the TODO list.
* `etimer` polling rather than CC-interrupt driven — the FLPR busy-loops between events. CC channel 3 wiring is the next major commit.
* `rtimer` is a stub. CC channel 4 will drive it later.
* No FLPR-side UART output — the FLPR shares its `printf` channel with the M33 only through the shared counter region. A proper IPC mailbox is a future commit.

## References

* Zephyr `drivers/misc/nordic_vpr_launcher/nordic_vpr_launcher.c` — canonical boot helper
* Zephyr `dts/vendor/nordic/nrf54l15_cpuflpr.dtsi` — FLPR memory layout
* Zephyr `snippets/nordic/nordic-flpr/soc/nrf54l15_cpuapp.overlay` — execution-memory / source-memory addresses
* nrfx `mdk/gcc_startup_nrf54l15_flpr.S`, `mdk/nrf54l15_xxaa_flpr.ld`, `hal/nrf_vpr.h`, `hal/nrf_spu.h`, `hal/nrf_grtc.h`
