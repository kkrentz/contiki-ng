#!/usr/bin/env python3
#
# Copyright (C) 2026 RISE Research Institutes of Sweden AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# SPDX-License-Identifier: BSD-3-Clause
#
"""
Trigger Nordic open-bootloader DFU mode on a PCA10059 dongle running
Contiki-NG firmware with USB DFU trigger support.

Sends the Nordic-vendor-specific DETACH control transfer that the
firmware's USB DFU trigger interface listens for, the same way the OLD
arch/cpu/nrf52840/usb/usb-dfu-trigger.c handler expected.

  bmRequestType = OUT | CLASS | DEVICE   (= 0x20)
  bRequest      = 0x00                   (DETACH)
  wValue        = 0
  wIndex        = 3                      (Contiki-NG's Nordic-DFU
                                          interface number; matches
                                          our usb_descriptors.c layout)
  wLength       = 0

The firmware receives this in nordic_dfu_trigger_control_xfer_cb() in
arch/cpu/nrf/dev/usb-arch.c, which then drives the dongle's self-reset
GPIO (P0.19) low to pin-reset the chip into the bootloader.

Usage:
  dongle-dfu-trigger.py                  # any dongle running the firmware
  dongle-dfu-trigger.py --serial-number <SN>
                                         # restrict to a specific dongle

Exits 0 on success or "device already in bootloader" (idempotent),
1 on hard errors.
"""
import argparse
import sys

try:
    import usb.core
    import usb.util
except ImportError:
    print("error: pyusb not installed (run: pip install pyusb)", file=sys.stderr)
    sys.exit(1)

VID = 0x1915
APP_PID = 0x520F   # Contiki-NG dongle app w/ DFU trigger
BL_PID = 0x521F    # Nordic open-bootloader in DFU mode


def _match_serial(serial):
    """Return a pyusb matcher that selects only devices whose USB
    iSerialNumber descriptor equals ``serial``. ``None`` selects any."""
    if serial is None:
        return lambda d: True

    def _check(d):
        try:
            return usb.util.get_string(d, d.iSerialNumber) == serial
        except (usb.core.USBError, ValueError):
            return False
    return _check


parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
parser.add_argument(
    "--serial-number",
    help="Restrict the trigger to the dongle with this USB serial number.",
)
args = parser.parse_args()

match = _match_serial(args.serial_number)

# If the bootloader is already enumerated for our target, there's nothing to do.
if usb.core.find(idVendor=VID, idProduct=BL_PID, custom_match=match) is not None:
    print("Dongle already in DFU bootloader mode.")
    sys.exit(0)

dev = usb.core.find(idVendor=VID, idProduct=APP_PID, custom_match=match)
if dev is None:
    msg = f"no dongle with VID:PID {VID:04X}:{APP_PID:04X}"
    if args.serial_number:
        msg += f" and serial number {args.serial_number}"
    print(f"error: {msg} found", file=sys.stderr)
    sys.exit(1)

bmRequestType = usb.util.build_request_type(
    usb.util.CTRL_OUT,
    usb.util.CTRL_TYPE_CLASS,
    usb.util.CTRL_RECIPIENT_DEVICE,
)

try:
    dev.ctrl_transfer(bmRequestType, 0x00, 0, 3, None, timeout=1000)
except usb.core.USBError:
    # Expected: the chip pin-resets in the middle of the control transfer.
    pass

print("DFU detach triggered.")
sys.exit(0)
