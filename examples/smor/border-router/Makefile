CONTIKI_PROJECT = border-router
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += $(CONTIKI_NG_SERVICES_DIR)/akes
MAKE_MAC = MAKE_MAC_CSL
MODULES += $(CONTIKI_NG_SERVICES_DIR)/smor
MAKE_ROUTING = MAKE_ROUTING_SMOR
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router
MODULES += $(CONTIKI_NG_SERVICES_DIR)/smor-webserver

include $(CONTIKI)/Makefile.include
