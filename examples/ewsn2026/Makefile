CONTIKI_PROJECT = name sink source
all: $(CONTIKI_PROJECT)

CONTIKI ?= ../..
include $(CONTIKI)/Makefile.dir-variables

MAKE_WITH_ORCHESTRA ?= 0
MAKE_WITH_RPL_STORING ?= 0
MAKE_WITH_D_UCB ?= 0
MAKE_WITH_RATE ?= 25
MAKE_WITH_WAKE_UP_RATE ?= 8

# configure rate
CFLAGS += -DSOURCE_CONF_RATE=$(MAKE_WITH_RATE)

# configure MAC protocol
ifeq ($(MAKE_WITH_ORCHESTRA),1)
# enable TSCH/Orchestra
MAKE_MAC = MAKE_MAC_TSCH
MODULES += $(CONTIKI_NG_SERVICES_DIR)/orchestra
CFLAGS += -DPROJECT_CONF_PATH=\"project-conf-tsch.h\"
ifeq ($(MAKE_WITH_RPL_STORING),1)
CFLAGS += -DORCHESTRA_CONF_RULES="{&eb_per_time_source,&unicast_per_neighbor_link_based,&default_common}"
endif
else
# enable HPI-MAC 
MODULES += $(CONTIKI_NG_SERVICES_DIR)/akes
MAKE_MAC = MAKE_MAC_CSL
CFLAGS += -DPROJECT_CONF_PATH=\"project-conf-csl.h\"
ifeq ($(MAKE_WITH_D_UCB),1)
CFLAGS += -DCSL_CHANNEL_SELECTOR_CONF_WITH_D_UCB=1
endif
CFLAGS += -DWAKE_UP_COUNTER_CONF_RATE=$(MAKE_WITH_WAKE_UP_RATE)
endif

# configure routing protocol
ifeq ($(MAKE_WITH_RPL_STORING),1)
MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC
endif

include $(CONTIKI)/Makefile.include
