LOCAL_PATH:= $(call my-dir)

regex_dir := $(LOCAL_PATH)/regex

include $(CLEAR_VARS)
LOCAL_MODULE := libapol
LOCAL_CFLAGS := -std=gnu99
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../include \
	$(LOCAL_PATH)/../libqpol/include \
	$(regex_dir)

LOCAL_SRC_FILES := \
	avrule-query.c \
	bool-query.c \
	bst.c \
	class-perm-query.c \
	condrule-query.c \
	constraint-query.c \
	context-query.c \
	domain-trans-analysis.c \
	fscon-query.c \
	infoflow-analysis.c \
	isid-query.c \
	mls-query.c \
	mls_level.c \
	mls_range.c \
	netcon-query.c \
	perm-map.c \
	permissive-query.c \
	polcap-query.c \
	policy.c \
	policy-path.c \
	policy-query.c \
	queue.c \
	range_trans-query.c \
	rbacrule-query.c \
	relabel-analysis.c \
	render.c \
	role-query.c \
	terule-query.c \
	ftrule-query.c \
	type-query.c \
	types-relation-analysis.c \
	user-query.c \
	util.c \
	vector.c \
	getline.c \
	regex/strlcpy.c \
	regex/regcomp.c  \
	regex/regerror.c  \
	regex/regexec.c  \
	regex/regfree.c


LOCAL_STATIC_LIBRARIES := libqpol

include $(BUILD_STATIC_LIBRARY)
