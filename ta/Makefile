# The UUID for the Trusted Application
BINARY = dba51a17-0563-11e7-93b1-6fa7b0071a51

ifeq ($(CFG_KMC),y)
CFLAGS_ta_arm64 += -DKMC -Wno-unused-function
CFLAGS_ta_arm32 += -DKMC -Wno-unused-function
endif

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
