CONTIKI_PROJECT = iot-device
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.identify-target

MODULES += os/services/akes
MODULES += os/services/filtering

ifeq ($(TARGET),cooja)
# Include software implementation of ECC
MODULES += os/services/ecc
endif

MAKE_MAC = MAKE_MAC_CSL
MODULES += os/services/smor
MAKE_ROUTING = MAKE_ROUTING_SMOR

include $(CONTIKI)/Makefile.include
