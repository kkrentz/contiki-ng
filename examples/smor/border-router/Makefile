CONTIKI_PROJECT = border-router
all: $(CONTIKI_PROJECT)
CONTIKI = ../../..

# The BR is either native or embedded, and in the latter case must support SLIP
PLATFORMS_EXCLUDE = z1

# Include RPL BR module
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router
# Include webserver module
MODULES_REL += webserver
# Include optional target-specific module
include $(CONTIKI)/Makefile.identify-target
MODULES_REL += $(TARGET)

MODULES += os/services/akes
MODULES += os/services/smor
MAKE_MAC = MAKE_MAC_CSL
MAKE_ROUTING = MAKE_ROUTING_SMOR

include $(CONTIKI)/Makefile.include
