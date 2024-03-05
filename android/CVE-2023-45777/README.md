# Mysterious patch

Let's start this time with the patch that appeared as fix for CVE-2023-45777 in [Android Security Bulletin](https://source.android.com/docs/security/bulletin/2023-12-01#framework):

```diff
diff --git a/services/core/java/com/android/server/accounts/AccountManagerService.java b/services/core/java/com/android/server/accounts/AccountManagerService.java
index 7a19d034c2c8..5238595fe2a2 100644
--- a/services/core/java/com/android/server/accounts/AccountManagerService.java
+++ b/services/core/java/com/android/server/accounts/AccountManagerService.java
@@ -4923,7 +4923,7 @@ public class AccountManagerService
             p.setDataPosition(0);
             Bundle simulateBundle = p.readBundle();
             p.recycle();
-            Intent intent = bundle.getParcelable(AccountManager.KEY_INTENT);
+            Intent intent = bundle.getParcelable(AccountManager.KEY_INTENT, Intent.class);
             if (intent != null && intent.getClass() != Intent.class) {
                 return false;
             }
```

Few people were puzzled by it enough to ask me, previously I've replied to them with some hints and now I'm publishing full writeup for this issue

But first lets provide some context about what is going on in this patch

This is change in [`checkKeyIntent()` method](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/accounts/AccountManagerService.java;l=4938-4954;drc=47de64a38aa1799cb41f41b2ea0c539ee61de64d). This method performs multiple checks to ensure that `Intent` provided by application is safe for system to launch (using privileges of system)

First, this method uses `checkKeyIntentParceledCorrectly()` which serializes and deserializes again `Bundle` which we're checking and checks if `Intent` taken from `Bundle` before that matches `Intent` from `Bundle` after such cycle. Since launch of `Intent` happens in other system app processes than one which performs validation, it was previously [possible to construct `Bundle`-s which appeared safe during validation inside `AccountManagerService`, but contained different `Intent` after being sent to next process](https://github.com/michalbednarski/IntentsLab/issues/2#issuecomment-344365482). This simulates sending `Bundle` to next process in order to detect such situations.

After `checkKeyIntentParceledCorrectly()` we have `bundle.getParcelable()` call, which this patch switches from deprecated version that could construct any object to one that validates that object that is about to be deserialized is of type which was specified in second parameter

That version with type parameter was introduced in Android 13, as part of larger `Parcel`/`Bundle` hardening. In particular, before Android 13 when `Bundle` was sent between processes, it kept raw copy of whole serialized data until any item was accessed, at which point every value was deserialized. Now when any value is accessed for first time after `Bundle` has been received, only `String` keys and the values of primitive types are deserialized, while non-primitive values are left as `LazyValue`-s, which have their length stored as part of serialized data in order to ensure that even when serialization/deserialization logic is mismatched, such mismatches won't affect other entries

Before we dive in, lets have a look at `LazyValue`: In it's source code [we've got nice comment explaining it's data structure](https://cs.android.com/android/platform/superproject/+/master:frameworks/base/core/java/android/os/Parcel.java;l=4392-4399;drc=03c34f57c05feecfb090de3917787f049cb5f804)

```
                     |   4B   |   4B   |
mSource = Parcel{... |  type  | length | object | ...}
                     a        b        c        d
length = d - c
mPosition = a
mLength = d - a
```

`mPosition` and `mLength` describe location of whole `LazyValue` data in original `Parcel`, including `type` and `length`. "`length`" (without "`m`" at beginning) refers to length value as written to `Parcel` and excludes header (`type` and `length`)

If `Bundle` containing `LazyValue` is being forwarded to another process, [whole `LazyValue` including `type` and `length` fields is copied verbatim from `Bundle.mParcelledData` to destination `Parcel`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/os/Parcel.java;l=4609-4617;drc=4d6b008243a5b1b1fb4e725e37e14651a24a4a4d)

When `Bundle` item represented by `LazyValue` is accessed, [`Parcel` is rewound to `mPosition` and `readValue()` is called](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/os/Parcel.java;l=4596-4597;drc=6f14f615c8f18a4467f0ae0539de58bddc9cc682). If type argument is passed to `bundle.getParcelable()`, it is propagated to `readValue()` which will both ensure that type about to be unparcelled is expected one as well as [verify after unparcelling that unparcelled value type is expected one](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/os/Parcel.java;l=4863-4867;drc=4d6b008243a5b1b1fb4e725e37e14651a24a4a4d). After unparcelling `LazyValue` is replaced so next time `Bundle` is written to `Parcel`, value will be serialized through `writeValue()` again

Use of typed `Bundle.get*()`/`Parcel.read*()` parameter is mostly relevant for methods such as [`Parcel.readParcelableList()`](https://developer.android.com/reference/android/os/Parcel#readParcelableList(java.util.List%3CT%3E,%20java.lang.ClassLoader,%20java.lang.Class%3C?%20extends%20T%3E)), which returns `ArrayList` and due to Java Type Erasure even if you did something like `List<SomeParcelableType> field = parcel.readParcelableList();`, the `<SomeParcelableType>` part wasn't enforced at runtime and such `List` could contain any `Parcelable` classes available in system and therefore all `createFromParcel`/`writeToParcel` available in system could be used as part of serialization/deserialization of type that contained such `List`

You might also want to check out [presentation from Android Security and Privacy team about introduction of these mechanisms](https://www.blackhat.com/eu-22/briefings/schedule/index.html#android-parcels-the-bad-the-good-and-the-better---introducing-androids-safer-parcel-28404) ([slides](http://i.blackhat.com/EU-22/Wednesday-Briefings/EU-22-Ke-Android-Parcels-Introducing-Android-Safer-Parcel.pdf), [video](https://youtube.com/watch?v=qIzMKfOmIAA))

Here however use of typed version appears to be redundant, as we also explicitly check type of returned object. So what is going on and what vulnerability is being fixed here?

# Side effects

Take a look at patch from beginning again

* If value deserialized under `"intent"` key is an `Intent`
  * It will be validated to point to component it is safe for system to launch
  * [If mismatch could be triggered from `Intent` object we'd have much bigger problem](https://github.com/michalbednarski/ReparcelBug2)
* If value being deserialized isn't `Intent`
  * In order to do anything bad, we'd need to have an `Intent` inside `Bundle` after it gets sent to another process, but type of `Parcelable` is saved at earlier offset than any possible mismatch and `LazyValue` length-prefixing prevents us from modifying next key-value pairs in case of `writeToParcel`/`createFromParcel` mismatch

So, what dangerous thing call to `bundle.getParcelable(AccountManager.KEY_INTENT)` without type argument could do here?

[Answer in next paragraph, try to guess before reading on. If I'd have a fursona this would be place for some art]

The answer is calling unrelated `createFromParcel()` that actually modifies of raw data of `LazyValue` that is stored under different key and will be passed verbatim to next process

We have a [`createFromParcel()`](https://developer.android.com/reference/android/os/Parcelable.Creator#createFromParcel(android.os.Parcel)) implementation that can actually call [`writeInt()`](https://developer.android.com/reference/android/os/Parcel#writeInt(int)) on provided `Parcel`

But not due to `writeInt` being mistakenly placed, but due to unrestricted reflection. In particular [inside `PackageParser` we have following code](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/content/pm/PackageParser.java;l=7789-7795;drc=7d3ffbae618e9e728644a96647ed709bf39ae759):

```java
final Class<T> cls = (Class<T>) Class.forName(componentName);
final Constructor<T> cons = cls.getConstructor(Parcel.class);

intentsList = new ArrayList<>(N);
for (int i = 0; i < N; ++i) {
    intentsList.add(cons.newInstance(in));
}
```

We can have `Parcel` object which was passed to `createFromParcel` passed to any available in system `public` constructor that accepts single `Parcel` argument

And then [we have following code](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/os/PooledStringWriter.java;l=51-56;drc=782d49826862cbdc9d020fc9d85f8a6f64675dcb):

```java
public PooledStringWriter(Parcel out) {
    mOut = out;
    mPool = new HashMap<>();
    mStart = out.dataPosition();
    out.writeInt(0); // reserve space for final pool size.
}
```

We've got constructor that calls `writeInt(0)` on provided `Parcel`, however there are few things that complicate exploitation

First of all, while it isn't directly visible in source code, immediately after `newInstance()` is called, a cast is performed and `ClassCastException` is thrown

# Swallow the Exception

I needed something that would during `createFromParcel` call `createFromParcel` of another class under `try` block and then fail to propagate caught Exception

This is part where exploit doesn't actually work on pure AOSP, I've used Samsung specific class

I've included [copy of relevant parts of that class in this repo](app/src/main/java/com/samsung/android/content/clipboard/data/SemImageClipData.java)

This repo also includes [script that integrates it into AOSP](make-aosp-buggy.sh), so for testing you can run it (pass path to your AOSP checkout as argument, e.g. `./make-aosp-buggy.sh /path/to/aosp`), revert change described at beginning of writeup and run this exploit against your AOSP build

[I've previously used `OutputConfiguration` class from AOSP for Exception swallowing](https://github.com/michalbednarski/ReparcelBug2#triggering-writetoparcelcreatefromparcel-mismatch), before Android 13 swallowing an Exception in `createFromParcel()` combined with allowing construction of other `Parcelable`-s is vulnerability in itself, however in case of `SemImageClipData` Exception swallowing wasn't present on these Android versions

There is however important difference between `SemImageClipData` and previously used `OutputConfiguration`: even though `SemImageClipData` catches an Exception, it still returns non-null object and if it will be later cast to another type, that would trigger `ClassCastException` which is what we're trying to avoid

# Java Type Erasure strikes back

Java Type Erasure means that generic methods don't actually know about generic type used by caller. This usually was helping exploitation

```java
// When we read some List, this actually didn't check if list contains only SomeParcelableType
List<SomeParcelableType> myList = sourceParcel.readParcelableList();

// Above is why Android 13 has introduced typed methods that enforce type at runtime
List<SomeParcelableType> myList = sourceParcel.readParcelableList(SomeParcelableType.class);

// If untyped method was used when reading, list can contain non-SomeParcelableType
// items and they would be written without errors
targetParcel.writeParcelableList(myList, 0);

// However if List contains non-SomeParcelableType item, this would throw during item access
// (That however commonly didn't happen if we used Parcelable object only as container in gadget chain)
SomeParcelableType myItem = myList.get(0);
```

This time type erasure didn't work in our favor. First we had method which actually invoked constructor through reflection

```java
private static <T extends IntentInfo> ArrayList<T> createIntentsList(Parcel in) {
    // ...
    final ArrayList<T> intentsList;
    // ...
    intentsList.add(cons.newInstance(in));
    // ...
    return intentsList;
}
```

This method has generic parameter `T`. It doesn't matter what parameter type was used by caller, however since in declaration of this method there's `<T extends IntentInfo>`, the line with `newInstance()` call becomes `intentsList.add((IntentInfo) cons.newInstance(in));`, even though `newInstance()` returns `Object` and `ArrayList.add()` accepts `Object` as argument. This introduced need to wrap call of that with some `Parcelable` that swallows Exception

Then we have the `bundle.getParcelable()` call

```java
@Deprecated
@Nullable
public <T extends Parcelable> T getParcelable(@Nullable String key) {
    unparcel();
    Object o = getValue(key);
    if (o == null) {
        return null;
    }
    try {
        return (T) o;
    } catch (ClassCastException e) {
        typeWarning(key, o, "Parcelable", e);
        return null;
    }
}
```

The deserialization procedure is performed by `getValue()` call, which actually leads to `createFromParcel()` call. If `ClassCastException` happens there it won't be caught. `getValue()` now returns whatever value was deserialized for this key through [`parcel.readValue()`](https://developer.android.com/reference/android/os/Parcel#readValue(java.lang.ClassLoader))

However if we put `SemImageClipData` as value, under `try`-`catch` we'd try to cast to `T`, which in this case is `Parcelable` as declared in methods generic declaration. Caller uses this method as generic with `T` being an `Intent`, however `getParcelable()` doesn't know that and cast to `Intent` happens in caller and therefore `ClassCastException` is thrown outside `try`

We can however wrap our `SemImageClipData` inside `Parcelable[]` array, then cast to `T` within `getParcelable()` will fail to cast `Parcelable[]` to `Parcelable` and will throw `ClassCastException` under `try`, that `Exception` will be logged and `null` will be returned and then accepted by `checkKeyIntent()` 

# The Layout

So now we need to align stuff within `Bundle` so after `writeToParcel`/`createFromParcel` cycle it's contents will be ones that we've prepared

But unlike typical "`Bundle` FengShui" where the trigger is having `createFromParcel` read more or less data than matching `writeToParcel` previously did, here we have `writeInt(0)` overwriting part of non-deserialized `LazyValue`

So here's how `Bundle.mParcelledData` looks when it is first unparcelled by `AccountManagerService` (Offsets taken by calling `dataPosition()` through debugger attached to `system_server`)

<table>
<tr><th>Offset</th><th>Value</th><th>Note</th></tr>
<tr><td>0</td><td>3</td><td>Number of key-value pairs</td></tr>
<tr><td>4</td><td>"intent"</td><td>First key in <code>Bundle</code>, the one that will be accessed by <code>getParcelable(AccountManager.KEY_INTENT)</code></td></tr>
<tr><td>24</td><td>16</td><td>First <code>LazyValue</code> starts here, type is <code>VAL_PARCELABLEARRAY</code></td></tr>
<tr><td>28</td><td>340</td><td>Declared length of <code>LazyValue</code>, used to find next key in <code>Bundle</code>. Our <code>LazyValue</code> won't actually have this size after being read, but <code>LazyValue.apply</code> <a href="https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/os/Parcel.java;l=4501-4505;drc=4d6b008243a5b1b1fb4e725e37e14651a24a4a4d">reports that through <code>Slog.wtfStack()</code></a> which <a href="https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/util/Slog.java;l=230-235;drc=4d6b008243a5b1b1fb4e725e37e14651a24a4a4d">doesn't throw</a></td></tr>
<tr><td>32</td><td>1</td><td>Length of <code>Parcelable[]</code> array, array has only one item and is present so <code>ClassCastException</code> happens inside <code>try</code> block that is in <code>bundle.getParcelable()</code></td></tr>
<tr><td>36</td><td>"com.samsung.android.<br>content.clipboard.data.<br>SemImageClipData"</td><td>Name of <code>Parcelable</code> class, this is wrapper class that will swallow Exception</td></tr>
<tr><td>160</td><td>2</td><td>Type tag used by <code>createClipBoardData()</code></td></tr>
<tr><td>164</td><td></td><td>Items that are read by <code>SemImageClipData</code> superclass constructor (which include <code>readParcelable()</code> call, however that happens outside <code>try</code> block). Not really relevant, but we need to go through them before reaching interesting part of <code>createFromParcel()</code></td></tr>
<tr><td>252</td><td></td><td>Data read by <code>SemImageClipData.readFromSource()</code></td></tr>
<tr><td>272</td><td>"android.content.pm.<br>PackageParser&#36;Activity"</td><td>Name of <code>Parcelable</code> read by <code>mExtraParcelFd = in.readParcelable()</code>. Type doesn't match, however before cast happens an Exception will be thrown anyway</td></tr>
<tr><td>360</td><td></td><td><code>className</code> &amp; <code>metadata</code> fields of <code>PackageParser$Component</code></td></tr>
<tr><td>368</td><td>1</td><td>Number of items in <code>createIntentsList()</code></td></tr>
<tr><td>372</td><td>"android.os.<br>PooledStringWriter"</td><td>Name of class that we'll be instantiated through <code>Class.forName().getConstructor(Parcel.class).newInstance()</code>. At this position first <code>LazyValue</code> ends, parsing of it however continues as <code>readValue()</code> didn't reach end. Also interpreted as second key in <code>Bundle</code> during initial <code>unparcel()</code></td></tr>
<tr><td>436</td><td>4</td><td>Second <code>LazyValue</code> starts here, this 4 is <code>VAL_PARCELABLE</code> for which <code>Parcel.isLengthPrefixed()</code> will return <code>true</code>. This value is later overwritten by <code>PooledStringWriter</code> constructor, after which an Exception is thrown and <code>getParcelable(AccountManager.KEY_INTENT)</code> finishes</td></tr>
<tr><td>440</td><td>240</td><td>Length of <code>LazyValue</code> whose type was declared to be <code>VAL_PARCELABLE</code>, this is used to determine position of next entry and how much data needs to be copied to target <code>Bundle</code> during re-serialization. This <code>LazyValue</code> is not actually unparcelled and is used as raw data container</td></tr>
<tr><td>684</td><td>"1&y~pw"</td><td rowspan="2">Third key/value pair, key is randomly generated to have Java <code>hashCode()</code> above previously used ones (Items stored inside <code>ArrayMap</code> are sorted by ascending <code>hashCode()</code> of key and that is the order items from <code>Bundle</code> will be written to <code>Parcel</code>). This key-value pair is present here only to increase total number of pairs written, as that will be number of pairs read, even though this pair actually won't be read</td></tr>
<tr><td>704</td><td>-1 (<code>VAL_NULL</code>)</td></tr>
</table>

Then, when Bundle is serialized again, it looks like that:

<table>
<tr><th>Offset</th><th>Value</th><th>Note</th></tr>
<tr><td>0</td><td>3</td><td>Number of key-value pairs</td></tr>
<tr><td>4</td><td>"intent"</td><td>First key in <code>Bundle</code></td></tr>
<tr><td>24</td><td>16</td><td><code>VAL_PARCELABLEARRAY</code>, previously deserialized <code>Parcelable[]</code> array is now being serialized again</td></tr>
<tr><td>28</td><td>196</td><td>Length of <code>LazyValue</code>, that is our wrapped <code>SemImageClipData</code> object. This length is taken from execution with my mock <code>SemImageClipData</code> and therefore offsets presented from this point on won't match ones that would appear on actual Samsung device, however this <code>LazyValue</code> won't be deserialized again so that doesn't matter for exploit execution</td></tr>
<tr><td>224</td><td>"android.os.<br>PooledStringWriter"</td><td>Second key in <code>Bundle</code></td></tr>
<tr><td>288</td><td>0</td><td>Second <code>LazyValue</code> starts here, item under <code>"android.os.PooledStringWriter"</code> key wasn't accessed, so this <code>LazyValue</code> is being copied from original data, however type tag was overwritten by <code>writeInt(0)</code> call done by <code>PooledStringWriter</code> constructor and upon reaching target process this is no longer interpreted as a <code>LazyValue</code></td></tr>
<tr><td>292</td><td>240</td><td>This was length of second <code>LazyValue</code> that was copied from original <code>Bundle</code>, however since type tag was overwritten with <code>writeInt(0)</code>, which is <code>VAL_STRING</code>, this value is now being read through <code>readString()</code>. Previously, for <code>LazyValue</code>, length was expressed in bytes, but now, for <code>String</code>, this is expressed in two-byte characters. There isn't enough data in source <code>Parcel</code> for that, so <a href="https://cs.android.com/android/platform/superproject/main/+/main:frameworks/native/libs/binder/Parcel.cpp;l=2221-2226;drc=4d6b008243a5b1b1fb4e725e37e14651a24a4a4d">native <code>parcel->readString16Inplace()</code> fails after reading length</a>, that however doesn't cause Exception on Java side</td></tr>
<tr><td>296</td><td>"intent"</td><td>"Third" key in <code>Bundle</code>. Actually overwrites first key: since <a href="https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/util/ArrayMap.java;l=651-659;drc=584140c83a456b5de99880b440c2d5dfc3c70506">"intent" has smaller <code>hashCode()</code> than previously seen key, <code>ArrayMap.append()</code> method uses <code>put()</code> which allows replacing values</a>, otherwise we'd <a href="https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/util/ArrayMap.java;l=667-675;drc=584140c83a456b5de99880b440c2d5dfc3c70506">have duplicate key which would be later rejected by <code>validate()</code></a></td></tr>
<tr><td>316</td><td>4</td><td><code>VAL_PARCELABLE</code>, here starts <code>LazyValue</code> containing actual <code>Intent</code> that will be started</td></tr>
<tr><td>536</td><td>"1&y~pw"</td><td>Padding item that was written but isn't read because all 3 key-value pairs were already read. <a href="https://cs.android.com/android/_/android/platform/system/tools/aidl/+/96a02f50fdfa4d20aa46ae2dde927257eac46d4a">Unlike AIDL interfaces</a>, there is no <code>enforceNoDataAvail()</code> check done on <code>Bundle</code> (but even if there were, it <a href="https://github.com/michalbednarski/ReparcelBug2/issues/3">could be bypassed by inserting dummy entry that specifies expected length</a>)</td></tr>
</table>

# How it happened twice

Lets now discuss four patches, two of which fix vulnerability this writeup is about

* CVE-2023-20944 ([bulletin](https://source.android.com/docs/security/bulletin/2023-02-01#framework), [patch](https://android.googlesource.com/platform/frameworks/base/+/d0bc9026e2e62e09fa88c1bcbf1dc1c3fb001375%5E%21/)): This is another vulnerability found by me. Similarly to this, patch doesn't make it obvious how it would be exploited, but [looks like someone else has figured it out (blog post in Chinese)](https://konata.github.io/posts/creator-mismatch/)
* CVE-2023-21098 ([bulletin](https://source.android.com/docs/security/bulletin/2023-04-01#framework), [patch](https://android.googlesource.com/platform/frameworks/base/+/107e6377328486fca55131ea06ca9d6a3c1585e0%5E%21/)): This is first time I reported exploit presented here. That patch also introduces fix for `checkKeyIntentParceledCorrectly()` bypass that is applicable to Android versions before 13
* CVE-2023-35669 ([bulletin](https://source.android.com/docs/security/bulletin/2023-09-01#framework), [patch](https://android.googlesource.com/platform/frameworks/base/+/f810d81839af38ee121c446105ca67cb12992fc6%5E%21/)): This one isn't in response to my report, but I think it was made to fix same issue as CVE-2023-20944 was about, but for cases where `AccountManager.KEY_INTENT` is launched by Activities other than `ChooseTypeAndAccountActivity` (for example [`AddAccountSettings`](https://cs.android.com/android/platform/superproject/main/+/main:packages/apps/Settings/src/com/android/settings/accounts/AddAccountSettings.java;l=95-107;drc=32813a2bef49b172aed89122b4eb50bf14026ddc), which I've missed when reporting bug first time). This change replaced use of typed `bundle.getParcelable()` use of untyped one and manual `getClass() != Intent.class` check, which actually reverted fix for CVE-2023-21098
* CVE-2023-45777 ([bulletin](https://source.android.com/docs/security/bulletin/2023-12-01#framework), [patch](https://android.googlesource.com/platform/frameworks/base/+/f4644b55d36a549710ba35b6fb797ba744807da6%5E%21/)): This is second time I reported this exploit. Patch kept manual `getClass() != Intent.class` check, but in addition to that brought back use of typed `bundle.getParcelable()`, which is good way to fix both issues

While same exploit works for both CVE-2023-21098 and CVE-2023-45777, way it happened to bypass `checkKeyIntentParceledCorrectly()` differs

In case of CVE-2023-21098, [`checkKeyIntent()` wasn't actually called if checked `Bundle` didn't have an `Intent`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/accounts/AccountManagerService.java;l=3519-3521;drc=cdd30b5c040ba7ebd0a1cc6009183ff602434fc0). As `checkKeyIntent()` is what calls `checkKeyIntentParceledCorrectly()`, in case when original `Bundle` didn't appear to contain an `Intent`, the `Bundle` after re-serialization wasn't checked

In case of CVE-2023-45777, `checkKeyIntentParceledCorrectly()` was correctly called, however [`writeBundle()` happened there before `getParcelable()` call without type argument (until which `Bundle` didn't change its contents)](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/accounts/AccountManagerService.java;l=4921-4929;drc=b0f6558fb36eb76df35c516ec5a65030a34a8734)
