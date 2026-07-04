CONTIKI_PROJECT = root leaf
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

MAKE_WITH_STORING_ROUTING ?= 0

MAKE_MAC = MAKE_MAC_TSCH
MODULES += $(CONTIKI_NG_SERVICES_DIR)/orchestra

ifeq ($(MAKE_WITH_STORING_ROUTING),1)
MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC
CFLAGS += -DORCHESTRA_CONF_RULES="{&eb_per_time_source,&unicast_per_neighbor_rpl_storing,&default_common}"
endif

include $(CONTIKI)/Makefile.include
