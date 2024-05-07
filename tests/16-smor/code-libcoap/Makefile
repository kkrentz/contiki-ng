all: echo-server echo-client

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += $(CONTIKI_NG_SERVICES_DIR)/akes
MAKE_MAC = MAKE_MAC_CSL
MODULES += $(CONTIKI_NG_SERVICES_DIR)/smor
MAKE_ROUTING = MAKE_ROUTING_SMOR
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/libcoap

include $(CONTIKI)/Makefile.include
