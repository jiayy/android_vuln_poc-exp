LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := pwn
LOCAL_SRC_FILES := pwn.c syscall.S

include $(BUILD_EXECUTABLE)
