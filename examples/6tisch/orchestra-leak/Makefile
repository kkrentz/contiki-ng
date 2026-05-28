CONTIKI_PROJECT = root node
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

MAKE_MAC = MAKE_MAC_TSCH
MODULES += $(CONTIKI_NG_SERVICES_DIR)/orchestra
CFLAGS += -DORCHESTRA_CONF_RULES="{&eb_per_time_source,&unicast_per_neighbor_rpl_ns,&default_common}"

include $(CONTIKI)/Makefile.include
