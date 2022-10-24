# Assume nkd-build is in the path
NDK_BUILD := NDK_PROJECT_PATH=. ndk-build NDK_APPLICATION_MK=./Application.mk
# Retrieve binary name from Android.mk
BIN := $(shell cat Android.mk | grep LOCAL_MODULE  | head -n1 | cut -d' ' -f3)

BIN_PATH := libs/arm64-v8a/$(BIN)

all: android 

$(BIN_PATH):
	$(NDK_BUILD)

android:
	@echo "Building Android"
	$(NDK_BUILD)

push: $(BIN_PATH) $(LOADER)
	adb push $(BIN_PATH) /data/local/tmp/$(notdir $(BIN_PATH))

shell: push
	adb shell /data/local/tmp/$(BIN)

clean:
	$(NDK_BUILD) clean
	-adb shell rm /data/local/tmp/$(notdir $(BIN_PATH))

distclean: clean
	$(RM) -rf libs obj
