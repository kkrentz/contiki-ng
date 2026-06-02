# flpr-minimal

Five-instruction RV32E "stamp" probe used during FLPR bring-up diagnostics.

The whole program is 20 bytes: write `0xCAFEBABE` to `0x2003F000` and spin.
If the M33-side launcher reads back `0xCAFEBABE` from the shared counter,
the VPR is actually executing instructions from the address pointed at by
INITPC. Useful when porting to a new board to confirm the boot dance works
*before* adding the full Contiki kernel.

## Build

    cd examples/flpr-minimal
    make all

Produces `flpr-stamp.bin` (20 bytes, RV32E).

## Use as the FLPR side of flpr-host

To run this instead of `hello-vpr.bin`, regenerate the blob header against
this binary and reflash the M33 image:

    cd examples/flpr-host
    python3 ../../tools/flpr-blob-gen.py ../flpr-minimal/flpr-stamp.bin > flpr-blob.h
    gmake TARGET=nrf BOARD=nrf54l15/dk WERROR=0 flpr-host.flash

Then look for `0xCAFEBABE` (= 3405691582) in the console output. If you see
it, the boot dance is correct and the problem is somewhere in your bigger
FLPR firmware.

See `doc/platforms/nrf-vpr.md` for the full port documentation.
