#!/bin/bash
set -xe
if [ $# != 1 ]; then
	echo Pass path to AOSP in argument
	exit 1
fi

AOSP_DIR="$1"
if ! [ -d "$AOSP_DIR/frameworks/base/core/java" ] || ! [ -f "$AOSP_DIR/build/soong/scripts/check_boot_jars/package_allowed_list.txt" ]; then
	echo "Provided path doesn't look like AOSP"
	exit 1
fi

SCRIPT_DIR="$( dirname -- "${BASH_SOURCE[0]}" )"
if ! [ -f "$SCRIPT_DIR/app/src/main/java/com/samsung/android/content/clipboard/data/SemImageClipData.java" ]; then
	echo "Cannot find source class"
	exit 1
fi

mkdir -p "$AOSP_DIR/frameworks/base/core/java/com/samsung/android/content/clipboard/data"
cp "$SCRIPT_DIR/app/src/main/java/com/samsung/android/content/clipboard/data/SemImageClipData.java" "$AOSP_DIR/frameworks/base/core/java/com/samsung/android/content/clipboard/data/SemImageClipData.java"
echo 'com\.samsung\.android\.content\.clipboard\.data' >> "$AOSP_DIR/build/soong/scripts/check_boot_jars/package_allowed_list.txt"
echo SUCCESS
