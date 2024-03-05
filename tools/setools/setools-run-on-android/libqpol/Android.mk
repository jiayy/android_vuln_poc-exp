LOCAL_PATH:= $(call my-dir)

bzip2_dir := bzip2

include $(CLEAR_VARS)
LOCAL_MODULE := libbz2
LOCAL_CFLAGS :=
LOCAL_C_INCLUDES := $(bzip2_dir)
LOCAL_SRC_FILES := \
	$(bzip2_dir)/blocksort.c  \
	$(bzip2_dir)/huffman.c    \
	$(bzip2_dir)/crctable.c   \
	$(bzip2_dir)/randtable.c  \
	$(bzip2_dir)/compress.c   \
	$(bzip2_dir)/decompress.c \
	$(bzip2_dir)/bzlib.c

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libqpol
LOCAL_CFLAGS := -std=gnu99
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/$(bzip2_dir) \
	$(LOCAL_PATH)/../include \
	$(LOCAL_PATH)/../libsepol/include

LOCAL_SRC_FILES := \
	avrule_query.c \
	bool_query.c \
	class_perm_query.c \
	cond_query.c \
	constraint_query.c \
	context_query.c \
	expand.c \
	fs_use_query.c \
	genfscon_query.c \
	isid_query.c \
	iterator.c \
	mls_query.c \
	mlsrule_query.c \
	module.c \
	module_compiler.c \
	netifcon_query.c \
	nodecon_query.c \
	permissive_query.c \
	polcap_query.c \
	policy.c \
	policy_define.c \
	policy_extend.c \
	portcon_query.c \
	queue.c \
	rbacrule_query.c \
	role_query.c \
	syn_rule_query.c \
	terule_query.c \
	ftrule_query.c \
	type_query.c \
	user_query.c \
	util.c \
	policy_parse.c \
	policy_scan.c

LOCAL_STATIC_LIBRARIES := libbz2 libsepol

include $(BUILD_STATIC_LIBRARY)
