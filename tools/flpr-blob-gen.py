#!/usr/bin/env python3
"""Generate flpr-blob.h from an FLPR firmware .bin.

Usage:
    python3 tools/flpr-blob-gen.py <flpr-firmware.bin> > examples/flpr-host/flpr-blob.h

The generated header exposes:
    FLPR_BLOB_LOAD_ADDR   - M33-bus address where the blob is copied at run time
    FLPR_BLOB_ENTRY_PC    - VPR INITPC (same as LOAD_ADDR for SRAM-resident builds)
    FLPR_SHARED_COUNTER   - shared SRAM word the M33 polls
    flpr_blob[]           - the raw firmware bytes, 4-byte aligned
    flpr_blob_len         - byte count

Used by examples/flpr-host to embed the FLPR firmware in the M33 image.
"""
import sys

data = open(sys.argv[1], 'rb').read()
print('/* Auto-generated from %s by tools/flpr-blob-gen.py */' % sys.argv[1])
print('#ifndef FLPR_BLOB_H')
print('#define FLPR_BLOB_H')
print('#include <stdint.h>')
print('#include <stddef.h>')
print()
print('#define FLPR_BLOB_LOAD_ADDR 0x20028000UL')
print('#define FLPR_BLOB_ENTRY_PC  0x20028000UL')
print('#define FLPR_SHARED_COUNTER (*(volatile uint32_t *)0x2003F000UL)')
print()
print('static const uint32_t flpr_blob_len = %u;' % len(data))
print('static const uint8_t flpr_blob[] __attribute__((aligned(4))) = {')
for i in range(0, len(data), 16):
    chunk = data[i:i+16]
    print('  ' + ', '.join('0x%02x' % b for b in chunk) + ',')
print('};')
print('#endif /* FLPR_BLOB_H */')
