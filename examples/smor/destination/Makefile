CONTIKI_PROJECT = destination
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

MODULES += os/net/app-layer/libcoap
MODULES += os/services/akes
MODULES += os/services/smor
MAKE_MAC = MAKE_MAC_CSL
MAKE_ROUTING = MAKE_ROUTING_SMOR

include $(CONTIKI)/Makefile.include
