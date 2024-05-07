CONTIKI_PROJECT = client server
all: $(CONTIKI_PROJECT)

CONTIKI = ../..
include $(CONTIKI)/Makefile.identify-target

MODULES += os/net/app-layer/libcoap
MODULES += os/net/app-layer/libcoap/src/oscore-ng
#MODULES += os/net/app-layer/libcoap/src/oscore

# for security on lower layers, uncomment these
#MAKE_MAC = MAKE_MAC_CSL
#MODULES += os/services/akes
#MAKE_ROUTING = MAKE_ROUTING_SMOR
#MODULES += os/services/smor

include $(CONTIKI)/Makefile.include
