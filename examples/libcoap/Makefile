CONTIKI_PROJECT = client server
all: $(CONTIKI_PROJECT)

CONTIKI = ../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/libcoap
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/libcoap/src/oscore-ng
#MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/libcoap/src/oscore

# for security on lower layers, uncomment these
#MAKE_MAC = MAKE_MAC_CSL
#MODULES += $(CONTIKI_NG_SERVICES_DIR)/akes
#MAKE_ROUTING = MAKE_ROUTING_SMOR
#MODULES += $(CONTIKI_NG_SERVICES_DIR)/smor

include $(CONTIKI)/Makefile.include
