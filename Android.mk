#
# Copyright (C) 2017 GlobalLogic
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Include only for HiKey ones in space separated list
# E.g. hikey hikey960 hikey970
ifneq (,$(filter $(TARGET_PRODUCT), hikey))
LOCAL_PATH:= $(call my-dir)

################################################################################
# Build keymaster HAL                                                          #
################################################################################
include $(CLEAR_VARS)

LOCAL_MODULE := android.hardware.keymaster@3.0-service.optee
LOCAL_INIT_RC := android.hardware.keymaster@3.0-service.optee.rc
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true

LOCAL_CFLAGS = -Wall -Werror
LOCAL_CFLAGS += -DANDROID_BUILD

LOCAL_SRC_FILES := \
	service.cpp \
	optee_keymaster.cpp \
	optee_keymaster_ipc.c

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/ta/include
#	external/optee-client/public \
#no need since optee-client/public is exported in optee_client/Android.mk

LOCAL_SHARED_LIBRARIES := \
	libteec \
	liblog \
	libhidlbase \
	libhidltransport \
	libhardware \
	libutils \
	libcutils \
	android.hardware.keymaster@3.0

include $(BUILD_EXECUTABLE)

################################################################################
# Build keymaster HAL TA                                                       #
################################################################################

# Please keep this variable consistent with TA_KEYMASTER_UUID define that
# defined in ta/include/common.h file
#TA_UUID:=dba51a17-0563-11e7-93b16fa7b0071a51
#TA_SRC:=$(LOCAL_PATH)/ta

#include $(LOCAL_PATH)/ta/build_executable.mk
include $(LOCAL_PATH)/ta/Android.mk

endif # Include only for HiKey ones.
