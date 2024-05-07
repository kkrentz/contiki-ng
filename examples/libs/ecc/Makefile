CONTIKI_PROJECT = compress ecdh ecdsa ecqv fhmqv
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.identify-target

# Includes software implementation of ECC
MODULES += os/services/ecc

include $(CONTIKI)/Makefile.include
