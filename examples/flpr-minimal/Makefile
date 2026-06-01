# Bare-metal probe — no Contiki, no nrfx startup. Just 4 instructions.
PROG = flpr-stamp
BIN  = $(PROG).bin
ELF  = $(PROG).elf
SRC  = flpr-stamp.S
LD   = flpr-stamp.ld

TC = $(HOME)/zephyr-toolchain-riscv/bin/riscv64-zephyr-elf
MARCH = rv32e_zicsr_zifencei
MABI  = ilp32e

all: $(BIN)

$(ELF): $(SRC) $(LD)
	$(TC)-gcc -march=$(MARCH) -mabi=$(MABI) -nostartfiles -nostdlib \
	    -T $(LD) -Wl,-eReset_Handler $< -o $@

$(BIN): $(ELF)
	$(TC)-objcopy -O binary $< $@

clean:
	rm -f $(BIN) $(ELF)
