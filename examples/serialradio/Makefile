CONTIKI_PROJECT = serial-radio-main
all: $(CONTIKI_PROJECT)

# Project source files
PROJECT_SOURCEFILES += serial-radio.c
PROJECT_SOURCEFILES += sniffer-mac.c

# Include CRC16 from Contiki-NG lib
MODULES += os/lib

# Include nullnet and CSMA (for TX support)
MODULES += os/net/nullnet
MODULES += os/net/mac/csma

CONTIKI = ../..
include $(CONTIKI)/Makefile.include
