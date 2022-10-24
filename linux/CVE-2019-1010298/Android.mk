LOCAL_PATH := $(call my-dir)

OPTEE_CLIENT_EXPORT ?= $(LOCAL_PATH)/../../optee_client/out/export

include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD
LOCAL_CFLAGS += -Wall

LOCAL_SRC_FILES += host/main.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/ta/include \
		    $(OPTEE_CLIENT_EXPORT)/include

LOCAL_SHARED_LIBRARIES := libteec
LOCAL_MODULE := cve_2019_1010298
LOCAL_VENDOR_MODULE := true
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

include $(LOCAL_PATH)/ta/Android.mk
