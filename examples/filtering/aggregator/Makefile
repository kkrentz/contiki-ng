CONTIKI_PROJECT = aggregator
all: $(CONTIKI_PROJECT)
CONTIKI = ../../..

# Include RPL BR module
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router
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
MODULES += os/services/smor
MAKE_ROUTING = MAKE_ROUTING_SMOR

include $(CONTIKI)/Makefile.include
