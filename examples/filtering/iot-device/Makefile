CONTIKI_PROJECT = iot-device
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.identify-target

MODULES += os/services/filtering
MODULES += os/services/akes

ifeq ($(TARGET),cooja)
# Include software implementation of ECC
MODULES += os/services/ecc
endif

MAKE_MAC = MAKE_MAC_CSL

include $(CONTIKI)/Makefile.include
