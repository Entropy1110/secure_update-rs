NAME := secure_update_host

TARGET ?= aarch64-unknown-linux-gnu
CROSS_COMPILE ?=
OBJCOPY := $(CROSS_COMPILE)objcopy
LINKER_CFG := target.$(TARGET).linker=\"$(CROSS_COMPILE)gcc\"

OUT_DIR := $(CURDIR)/target/$(TARGET)/release

.PHONY: all host strip clean

all: host strip

host:
	@cargo build --target $(TARGET) --release --config $(LINKER_CFG)

strip: host
	@$(OBJCOPY) --strip-unneeded $(OUT_DIR)/$(NAME) $(OUT_DIR)/$(NAME)

clean:
	@cargo clean
