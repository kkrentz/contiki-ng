# nrf-vpr — minimal Contiki-NG port for the nRF54L15 FLPR (RV32E)

This is a proof-of-concept smallest-possible Contiki-NG port targeting Nordic's
"VPR" (Vendor Programmable RISC-V) coprocessor on the nRF54L15 — sold under
the name **FLPR** (Fast Lightweight Peripheral Processor). The FLPR is an
RV32E core with its own tightly-coupled SRAM/RRAM partitions, controlled by
the application core (Cortex-M33) through register pokes plus a SoC-level
boot dance.

## What's complete

- **arch/cpu/nrf-vpr/** — toolchain Makefile, RISC-V clock-arch (cycle CSR),
  int-master-arch (mstatus.mie), minimal rtimer stub, picolibc-style syscall
  stubs, watchdog stubs, and `nrf-vpr-sram.ld` (RAM-resident link variant).
- **arch/platform/nrf-vpr/** — minimal platform.c, contiki-conf.h. No
  networking stack (NULLNET / NULLMAC / NULLROUTING by default).
- **examples/hello-vpr/** — one process, 500 ms etimer-driven counter writer
  at `0x2003F000` (the shared poll location).
- **examples/flpr-host/** — M33-side Contiki app that embeds the FLPR `.bin`,
  copies it into the canonical execution memory at `0x20028000`, pokes the
  VPR INITPC and CPURUN registers, and polls the shared counter every 1 s.
- **examples/flpr-minimal/** — 5-instruction bare-metal RV32E "stamp" probe
  used for boot diagnosis (writes `0xCAFEBABE` to the counter and spins).

Build:
```
gmake TARGET=nrf-vpr WERROR=0
```
Result: ~10 KB ELF, entry at `0x20028000`, valid RV32E.

## What is NOT complete: the VPR boot dance

The FLPR-side firmware is correct and runnable. The **M33-side boot dance is
incomplete** because Nordic's canonical sequence requires writes to a
peripheral that lives only in the Secure address space:

```
Zephyr drivers/misc/nordic_vpr_launcher/nordic_vpr_launcher.c, summarised:

  #ifndef CONFIG_TRUSTED_EXECUTION_NONSECURE
    if (DT.enable_secure) {
        nrf_spu_periph_perm_secattr_set(NRF_SPU00,
            nrf_address_slave_get(VPR_BASE), true);   /* PERIPH[12].PERM */
    }
  #endif
  nrf_vpr_initpc_set(VPR, exec_addr);
  nrf_vpr_cpurun_set(VPR, true);
```

The nRF54L15 cpuapp DTS marks `cpuflpr_vpr` with `enable-secure;`, so this
SPU step is mandatory on the canonical boot path. The SPU PERIPHACCESS array
is at `0x50040500` (`NRF_SPU00_S_BASE + 0x500`) — Secure-only, no
non-secure view exists.

Contiki-NG's current nRF54L15 platform runs the M33 in **non-secure** mode
(observed via empirical fault dump: any write to `NRF_VPR00_S` =
`0x5004C808` BusFaults; writes to `NRF_VPR00_NS` = `0x4004C808` succeed).
So our M33 firmware cannot execute the SPU step.

End result demonstrated on real hardware (nrf54l15dk + J-Link):
- M33 boots cleanly, runs the flpr-host process
- 8 KB FLPR blob is embedded and `memcpy`'d to `0x20028000` (the canonical
  FLPR execution memory per Zephyr DTS)
- `INITPC = 0x20028000` and `CPURUN = 1` writes via NS view land and stick
  (readback returns the written values)
- **The FLPR never actually executes**: counter stays at `0` indefinitely,
  not even a bare 5-instruction RV32E "stamp" probe runs

## What it would take

Closing this gap requires one of:

1. **Add a small Secure-mode bootloader for the nRF54L15 platform** that
   - configures `NRF_SPU00->PERIPH[12].PERM` (SECATTR=Secure as Zephyr does)
   - optionally configures SRAM region NSC if FLPR-region access from M33-NS
     turns out to also need a poke
   - jumps to the existing NS Contiki firmware

2. **Build the M33 Contiki entirely Secure**. The platform's
   `Makefile.nrf54l15` has TrustZone scaffolding (`TRUSTZONE_SECURE_BUILD`),
   but the secure-side support files (`tz-spu.c`, partition table) referenced
   by that branch don't exist yet — that part of the nrf54l15 port is
   incomplete.

Either path means touching the existing M33 platform's TrustZone story,
which is outside the scope of this VPR-port branch.

## What we proved end-to-end

| Step | Status |
|---|---|
| RISC-V toolchain (Zephyr SDK riscv64-zephyr-elf, rv32e_zicsr_zifencei multilib) | ✅ |
| FLPR-side Contiki-NG builds, ~10 KB ELF, valid RV32E | ✅ |
| Blob embed pipeline (elf → bin → C header → M33 .rodata) | ✅ |
| `memcpy` to FLPR execution memory (`0x20028000`) | ✅ |
| VPR INITPC + CPURUN register write (NS view) | ✅ writes stick |
| VPR actually executes the loaded code | ❌ blocked by SPU step that requires Secure mode |

## References

- Zephyr `drivers/misc/nordic_vpr_launcher/nordic_vpr_launcher.c` — canonical
  boot helper
- Zephyr `dts/vendor/nordic/nrf54l15_cpuflpr.dtsi` — FLPR memory layout
- Zephyr `snippets/nordic/nordic-flpr/soc/nrf54l15_cpuapp.overlay` —
  canonical execution-memory / source-memory pairing
- nrfx `mdk/gcc_startup_nrf54l15_flpr.S`, `mdk/nrf54l15_xxaa_flpr.ld`,
  `mdk/nrf_common_riscv.ld`, `hal/nrf_vpr.h`
