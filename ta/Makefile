# The UUID for the Trusted Application
BINARY = dba51a17-0563-11e7-93b1-6fa7b0071a51

#ifdef TA_CROSS_COMPILE
#CROSS_COMPILE ?= $(TA_CROSS_COMPILE)
#endif
#export CROSS_COMPILE

#CFG_TEE_TA_LOG_LEVEL ?= 2
#CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

#ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
#clean:
#	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
#	@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
#endif
