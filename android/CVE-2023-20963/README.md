# BadParcel

See [Bundle Fengshui](https://chal13w1zz.github.io/posts/bundle-fengshui-android-s-self-changing-bundle/) for a deep dive on this bug class.

This repositiory contains PoC for [CVE-2023-20963](https://source.android.com/docs/security/bulletin/2023-03-01#framework), which is mismatch in the Android WorkSource parcel/unparcel logic.

The vulnerability is patched on Android's Security Bulletin of March 2023. The exploit should work on devices on AOSP versions 11, 12, 12L, 13 with security patch levels prior to March 2023. 

## [Screen Lock Bypass with CVE-2023-20963 POC](https://twitter.com/i/status/1675460923664760832)

![Screen Lock Bypass POC](assets/CVE-2023-20963.gif)
