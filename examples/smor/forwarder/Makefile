CONTIKI_PROJECT = forwarder
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.identify-target

MODULES += os/services/akes
MAKE_MAC = MAKE_MAC_CSL
MODULES += os/services/smor
MAKE_ROUTING = MAKE_ROUTING_SMOR

include $(CONTIKI)/Makefile.include
