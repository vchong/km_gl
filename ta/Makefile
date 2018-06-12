CFG_TEE_TA_LOG_LEVEL ?= 0
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

all: $(out-dir)/$(BINARY).ta

clean: clean_ta_file
.PHONY: clean_ta_file
clean_ta_file:
	rm -f $(out-dir)/$(BINARY).ta
