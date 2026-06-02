# nrf-vpr — minimal Contiki-NG port for the nRF54L15 FLPR (RV32E)

Smallest-possible Contiki-NG port targeting Nordic's **FLPR** (Fast Lightweight
Peripheral Processor) — an RV32E coprocessor on the nRF54L15 with its own
tightly-coupled SRAM/RRAM partitions, controlled by the application core
(Cortex-M33) through register pokes plus a SoC-level boot dance.

## Status

**End-to-end working** on real hardware (nRF54L15-DK):

- FLPR boots, full Contiki kernel runs, process scheduler + etimer cycling
  at thousands of iterations per second
- M33 launches the FLPR using the canonical Zephyr/Nordic boot dance
- Single openocd / J-Link session flashes both M33 image and embedded
  FLPR blob

Current limitation: **clock_time() uses a software-advanced fake counter**
(advances one tick per call). Etimer works because all timer state is
internally consistent, but wall-clock timing is wrong. The follow-up commit
wires GRTC SYSCOUNTER for proper time.

## Layout

| Component | Path | Purpose |
|---|---|---|
| CPU port | `arch/cpu/nrf-vpr/` | toolchain Makefile, clock-arch, int-master, rtimer, picolibc-style syscall stubs, mem*-stubs, watchdog stubs, trap handler |
| Platform | `arch/platform/nrf-vpr/` | minimal platform.c + contiki-conf.h |
| FLPR example | `examples/hello-vpr/` | one process, etimer-driven counter at `0x2003F000` |
| M33 launcher | `examples/flpr-host/` | embeds the FLPR blob, runs the boot dance, polls the shared counter, prints over UART |
| Probe | `examples/flpr-minimal/` | 5-instruction bare-metal RV32E probe used during boot diagnosis |

## Build

```
cd examples/hello-vpr
gmake TARGET=nrf-vpr WERROR=0
```

Result: `~8 KB` ELF, entry at `0x20028000`, valid RV32E.

```
cd examples/flpr-host
gmake TARGET=nrf BOARD=nrf54l15/dk WERROR=0 flpr-host.flash
```

The M33 image embeds `examples/hello-vpr/build/nrf-vpr/hello-vpr.bin` as a
C array (`examples/flpr-host/flpr-blob.h`, regenerate with the same
`flpr-blob-gen.py` after FLPR rebuilds).

## The boot dance (M33-side, identical to Zephyr's `nordic_vpr_launcher`)

```c
/* 1. memcpy blob into FLPR execution memory */
memcpy((void *)0x20028000, flpr_blob, flpr_blob_len);

/* 2. Mark VPR00 as Secure in SPU PERIPHACCESS  ← critical step */
NRF_SPU00_S->PERIPH[12].PERM |= (1u << 4);  /* SECATTR=Secure */

/* 3. Set entry PC */
NRF_VPR00_S->INITPC = 0x20028000;

/* 4. Release the VPR core */
NRF_VPR00_S->CPURUN  = 1;
```

All four steps run from the Secure world (Contiki on nRF54L15 boots Secure
by default; no NS transition is performed).

## Two gotchas that took the longest to find

### (a) SPU PERIPHACCESS for VPR00

By default the VPR's `PERIPH[12].PERM` register has `SECATTR=0`. In that
state the VPR appears to "start" (CPURUN sticks at 1, INITPC accepts the
write), but it never actually executes instructions from the supplied
address. Setting `SECATTR=Secure` is what makes the VPR fetch.

Zephyr's `drivers/misc/nordic_vpr_launcher/nordic_vpr_launcher.c` does the
same thing under the `enable_secure` DT flag, which the cpuapp DTS for
nRF54L15 has set unconditionally on `cpuflpr_vpr`.

### (b) nrfx startup needs `-D__STARTUP_CLEAR_BSS`

`mdk/gcc_startup_nrf54l15_flpr.S` only emits the `.bss`/`.sbss`/`.tbss`
zero-init loops when `__STARTUP_CLEAR_BSS` is defined. Without it, BSS
is left at whatever garbage was in SRAM. Contiki globals (`process_list`,
`process_current`, `timerlist`, etc.) hold random values, and the kernel
hangs the moment it touches them. `arch/cpu/nrf-vpr/Makefile.nrf-vpr`
defines this; if you copy the toolchain settings elsewhere, copy this
too.

## Other implementation notes

- **Linker script:** `arch/cpu/nrf-vpr/nrf-vpr-sram.ld` lays out
  `.text/.rodata` at `0x20028000` (start of the FLPR's reserved 96 KB
  SRAM block per the Zephyr cpuflpr DTS), `.data/.bss/stack` at `0x20030000`.
- **Position-independent code:** `-mcmodel=medany`. Required because we
  link for SRAM addresses, not RRAM 0x0.
- **picolibc avoided:** the linker script's `GROUP(-lgcc -lc)` wants libc;
  we link `-nostdlib -lgcc` and provide our own `memset/memcpy/memmove/memcmp`
  in `startup-stubs.c` so we don't need libc at all.
- **Trap handler:** the nrfx-provided `Trap_Handler` is a silent infinite
  loop. We override `mtvec` in `_start()` to point at `my_trap_handler`
  which writes `0xFA1100|mcause` to `0x2003F000` and `mepc` to `0x2003F004`
  before spinning. The M33 polls both addresses so any fault is visible.

## Hardware-validated path on nRF54L15-DK

```
[INFO: flpr-host ] M33 boot complete, blob=N bytes
[INFO: flpr-host ] Blob memcpy'd to 0x20028000
[INFO: flpr-host ] SPU PERIPH[12] before=0x8001000a after=0x8001001a
[INFO: flpr-host ] M33 is in SECURE mode (SPU S access succeeded)
[INFO: flpr-host ] VPR_S after launch: INITPC=0x20028000 CPURUN=0x1
[INFO: flpr-host ] [FLPR] tick 2026
[INFO: flpr-host ] [FLPR] tick 4047    ← ~2000 etimer cycles/s with the fake clock
...
```

## Next steps

Real clock source via GRTC SYSCOUNTER and CC channels.

GRTC channel partitioning (matches the Zephyr/Nordic split, so the two
Contiki-NG sides never collide on a CC channel):

| Core | Owned GRTC channels |
|---|---|
| CPUAPP / M33 Contiki-NG | 0, 1, 2, 5, 6 |
| FLPR / VPR Contiki-NG   | **3, 4** |

FLPR-side use of its two channels:

| GRTC resource | Use |
|---|---|
| SYSCOUNTER (poll)        | `clock_time()`, `clock_seconds()`, `clock_delay_usec()` |
| FLPR CC channel **3**    | etimer / Contiki clock tick (next-compare interrupt) |
| FLPR CC channel **4**    | rtimer (or reserve) |

Zephyr's cpuflpr DTS confirms this: `owned-channels = <3 4>;` on the
FLPR side, and CPUAPP marks those as child-owned.

## References

- Zephyr `drivers/misc/nordic_vpr_launcher/nordic_vpr_launcher.c`
- Zephyr `dts/vendor/nordic/nrf54l15_cpuflpr.dtsi`
- Zephyr `snippets/nordic/nordic-flpr/soc/nrf54l15_cpuapp.overlay`
- nrfx `mdk/gcc_startup_nrf54l15_flpr.S`, `mdk/nrf54l15_xxaa_flpr.ld`,
  `hal/nrf_vpr.h`, `hal/nrf_spu.h`, `hal/nrf_grtc.h`
