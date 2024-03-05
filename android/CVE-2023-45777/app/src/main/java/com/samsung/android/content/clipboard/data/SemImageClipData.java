package com.samsung.android.content.clipboard.data;

import android.content.ClipData;
import android.net.Uri;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import android.os.PersistableBundle;
import android.text.TextUtils;
import android.util.Log;

import java.util.ArrayList;

/** @hide */
public class SemImageClipData implements Parcelable {

    // Simulates relevant parts of SemImageClipData found on Samsung devices
    // Tested on
    // adb shell getprop ro.build.fingerprint
    // samsung/o1sxeea/o1s:13/TP1A.220624.014/G991BXXS5DVK1:user/release-keys

    protected SemImageClipData(Parcel in) {
        // BEGIN superclass constructor
        int mType = in.readInt();
        long mTimestamp = in.readLong();
        boolean mIsProtected = (Boolean) in.readValue(Boolean.class.getClassLoader());
        long mCallerUid = in.readLong();
        ClipData mClipData = in.readParcelable(ClipData.class.getClassLoader());
        ParcelFileDescriptor mParcelFd = in.readParcelable(ParcelFileDescriptor.class.getClassLoader());
        String mClipId = in.readString();
        ArrayList<String> mMimeTypes = in.createStringArrayList();
        CharSequence mLabel = TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(in);
        ArrayList mKeyList = in.readArrayList(Object.class.getClassLoader());
        ArrayList mObjList = in.readArrayList(Object.class.getClassLoader());
        PersistableBundle mBundle = in.readPersistableBundle();
        boolean mIsPCClip = (Boolean) in.readValue(Boolean.class.getClassLoader());
        boolean mIsRemoteClip = (Boolean) in.readValue(Boolean.class.getClassLoader());
        String mRemoteClipId = in.readString();
        int mRemoteState = in.readInt();
        // END superclass constructor
        readFromSource(in);
    }

    protected void readFromSource(Parcel in) {
        try {
            String mImagePath = in.readString();
            String contentUriString = in.readString();
            Uri mContentUri = contentUriString != null ? Uri.parse(contentUriString) : null;
            String mInitBaseValue = in.readString();
            boolean mInitBaseValueCheck = in.readByte() != 0;
            String mExtraDataPath = in.readString();
            ParcelFileDescriptor mExtraParcelFd = in.readParcelable(ParcelFileDescriptor.class.getClassLoader());
        } catch (Exception e) {
            // Log and continue
            Log.i("SemImageClipData", "Exception thrown during readFromSource", e);
        }
    }

    public static final Creator<SemImageClipData> CREATOR = new Creator<SemImageClipData>() {
        @Override
        public SemImageClipData createFromParcel(Parcel in) {
            // This switch is normally in <android.sec.clipboard.data.ClipboardDataFactory: com.samsung.android.content.clipboard.data.SemClipData createClipBoardData(android.os.Parcel)>
            // Which is called from <com.samsung.android.content.clipboard.data.SemClipData$1: com.samsung.android.content.clipboard.data.SemClipData createFromParcel(android.os.Parcel)>
            switch (in.readInt()) {
            case 2:
                return new SemImageClipData(in);
            default:
                // Other values are not relevant here
                throw new UnsupportedOperationException();
            }
        }

        @Override
        public SemImageClipData[] newArray(int size) {
            return new SemImageClipData[size];
        }
    };

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString("THIS SHOULD NOT BE READ AGAIN");
    }
}