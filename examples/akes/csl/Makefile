CONTIKI_PROJECT = sender receiver
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MAKE_MAC = MAKE_MAC_CSL
MODULES += $(CONTIKI_NG_SERVICES_DIR)/akes
MAKE_NET = MAKE_NET_NULLNET

include $(CONTIKI)/Makefile.include
