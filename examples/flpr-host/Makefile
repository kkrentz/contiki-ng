CONTIKI_PROJECT = flpr-host
all: $(CONTIKI_PROJECT)

CONTIKI = ../..
TARGET ?= nrf
BOARD ?= nrf54l15/dk

# Sub-project: the FLPR firmware that gets embedded in this M33 image.
FLPR_DIR        := $(CONTIKI)/examples/hello-vpr
FLPR_BIN        := $(FLPR_DIR)/build/nrf-vpr/hello-vpr.bin
FLPR_BLOB_GEN   := $(CONTIKI)/tools/flpr-blob-gen.py

# Build the FLPR firmware and (re)generate flpr-blob.h before Contiki's
# pattern rules try to compile flpr-host.c. Runs at make-load time so the
# header exists by the time the .c is compiled. Skipped for clean targets.
# BOARD= unsets the inherited M33 BOARD when invoking the FLPR sub-make.
# The cmp/mv dance avoids touching flpr-blob.h's mtime when content is
# unchanged, so flpr-host.c only rebuilds when the FLPR firmware actually
# changed.
ifeq ($(filter clean distclean,$(MAKECMDGOALS)),)
  $(info nrf-vpr: ensuring FLPR firmware is up to date...)
  FLPR_BUILD_LOG := $(shell $(MAKE) --no-print-directory -C $(FLPR_DIR) \
                              TARGET=nrf-vpr BOARD= WERROR=0 hello-vpr.bin 2>&1)
  ifneq ($(.SHELLSTATUS),0)
    $(error FLPR build failed:$(FLPR_BUILD_LOG))
  endif
  IGNORE := $(shell python3 $(FLPR_BLOB_GEN) $(FLPR_BIN) > flpr-blob.h.tmp && \
              if cmp -s flpr-blob.h.tmp flpr-blob.h 2>/dev/null; \
              then rm flpr-blob.h.tmp; \
              else mv flpr-blob.h.tmp flpr-blob.h; fi)
endif

CLEAN += flpr-blob.h flpr-blob.h.tmp

include $(CONTIKI)/Makefile.include
