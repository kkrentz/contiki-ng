CONTIKI_PROJECT = aggregator
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables
include $(CONTIKI)/Makefile.identify-target

ifeq ($(TARGET),cooja)
# Include software implementation of ECC
MODULES += $(CONTIKI_NG_SERVICES_DIR)/ecc
endif

MODULES += $(CONTIKI_NG_SERVICES_DIR)/akes
MAKE_MAC = MAKE_MAC_CSL
MODULES += $(CONTIKI_NG_SERVICES_DIR)/smor
MAKE_ROUTING = MAKE_ROUTING_SMOR
MODULES += $(CONTIKI_NG_SERVICES_DIR)/filtering
# MODULES += $(CONTIKI_NG_SERVICES_DIR)/tiny-dice # uncomment for mutual attestation
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router

include $(CONTIKI)/Makefile.include
