NAME := secure_update_server

TARGET ?= aarch64-unknown-linux-gnu
CROSS_COMPILE ?=
OBJCOPY := $(CROSS_COMPILE)objcopy
LINKER_CFG := target.$(TARGET).linker=\"$(CROSS_COMPILE)gcc\"

OUT_DIR := $(CURDIR)/target/$(TARGET)/release

.PHONY: all server strip clean

all: server strip

server:
	@cargo build --target $(TARGET) --release --config $(LINKER_CFG)

strip: server
	@$(OBJCOPY) --strip-unneeded $(OUT_DIR)/$(NAME) $(OUT_DIR)/$(NAME)

clean:
	@cargo clean
