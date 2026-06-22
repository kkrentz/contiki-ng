#!/usr/bin/env python3
"""
Serial Radio CLI launcher script.

Usage:
    pixi run cli /dev/ttyUSB0
    ./serialradio.py /dev/tty.usbserial-1234
"""

from tools.cli import main

if __name__ == '__main__':
    main()
