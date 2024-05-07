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
MODULES += $(CONTIKI_NG_SERVICES_DIR)/filtering
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router

include $(CONTIKI)/Makefile.include
