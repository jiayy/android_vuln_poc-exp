LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := payload
LOCAL_CFLAGS += -Iinclude
LOCAL_SRC_FILES := src/reverse_shell.c

#include $(BUILD_EXECUTABLE)
include $(BUILD_SHARED_LIBRARY)


