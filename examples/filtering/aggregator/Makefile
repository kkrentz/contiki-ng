CONTIKI_PROJECT = aggregator
all: $(CONTIKI_PROJECT)
CONTIKI = ../../..

# The BR is either native or embedded, and in the latter case must support SLIP
PLATFORMS_EXCLUDE = nrf52dk z1
BOARDS_EXCLUDE = nrf52840/dongle

# Include RPL BR module
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router
# Include webserver module
MODULES_REL += webserver
# Include optional target-specific module
include $(CONTIKI)/Makefile.identify-target
MODULES_REL += $(TARGET)

MODULES += os/services/akes
MODULES += os/services/filtering

ifeq ($(TARGET),cooja)
# Include software implementation of ECC
MODULES += os/services/ecc
endif

MAKE_MAC = MAKE_MAC_CSL

include $(CONTIKI)/Makefile.include
