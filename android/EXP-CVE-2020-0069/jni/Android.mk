LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := kernel_rw
LOCAL_SRC_FILES := kernel_rw.c
LOCAL_C_INCLUDES := jni/
cmd-strip :=
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := syscall_hook
LOCAL_SRC_FILES := syscall_hook.c
include $(BUILD_SHARED_LIBRARY)

$(call import-add-path, $(LOCAL_PATH))

