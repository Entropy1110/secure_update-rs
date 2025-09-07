UUID ?= $(shell cat "../uuid.txt")

TARGET ?= aarch64-unknown-linux-gnu
CROSS_COMPILE ?= aarch64-linux-gnu-
OBJCOPY := $(CROSS_COMPILE)objcopy
# Configure the linker to use GCC, which works on both cross-compilation and ARM machines
LINKER_CFG := target.$(TARGET).linker=\"$(CROSS_COMPILE)gcc\"

TA_SIGN_KEY ?= $(TA_DEV_KIT_DIR)/keys/default_ta.pem
SIGN := $(TA_DEV_KIT_DIR)/scripts/sign_encrypt.py
OUT_DIR := $(CURDIR)/target/$(TARGET)/release

BUILDER = $(if $(STD),xargo,cargo)

.PHONY: all ta strip sign clean

all: ta strip sign

ta:
	@$(BUILDER) build --target $(TARGET) --release --config $(LINKER_CFG)

strip: ta
	@$(OBJCOPY) --strip-unneeded $(OUT_DIR)/ta $(OUT_DIR)/stripped_ta

sign: strip
	@$(SIGN) --uuid $(UUID) --key $(TA_SIGN_KEY) --in $(OUT_DIR)/stripped_ta --out $(OUT_DIR)/$(UUID).ta
	@echo "SIGN =>  ${UUID}"

clean:
	@cargo clean
