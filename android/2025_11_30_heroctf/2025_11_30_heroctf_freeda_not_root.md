# Overview
This writeup details the reverse engineering of an Android application that requires a password input. The goal is to reverse engineer the flag validation mechanism and extract the correct flag.

## Initial analysis
First, the `AndroidManifest.xml` is examined to understand the app structure. Analysis reveals only one activity called MainActivity.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="36" android:compileSdkVersionCodename="16" package="com.heroctf.freeda1" platformBuildVersionCode="36" platformBuildVersionName="16">
    <uses-sdk android:minSdkVersion="30" android:targetSdkVersion="35"/>
    <permission android:name="com.heroctf.freeda1.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature"/>
    <uses-permission android:name="com.heroctf.freeda1.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application android:theme="@style/Theme.Freeda1" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="true" android:supportsRtl="true" android:extractNativeLibs="false" android:fullBackupContent="@xml/backup_rules" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules">
        <activity android:name="com.heroctf.freeda1.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <provider android:name="androidx.startup.InitializationProvider" android:exported="false" android:authorities="com.heroctf.freeda1.androidx-startup">
            <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer" android:value="androidx.startup"/>
            <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer" android:value="androidx.startup"/>
            <meta-data android:name="androidx.profileinstaller.ProfileInstallerInitializer" android:value="androidx.startup"/>
        </provider>
        <receiver android:name="androidx.profileinstaller.ProfileInstallReceiver" android:permission="android.permission.DUMP" android:enabled="true" android:exported="true" android:directBootAware="false">
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.INSTALL_PROFILE"/>
            </intent-filter>
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.SKIP_FILE"/>
            </intent-filter>
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.SAVE_PROFILE"/>
            </intent-filter>
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.BENCHMARK_OPERATION"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

## Java analysis
Next, the APK is decompiled with `jadx-gui` to examine `MainActivity.java`. The `onCreate` method reveals that the button's click listener handles flag validation.

```java
package com.heroctf.freeda1;

import android.content.res.Resources;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import java.util.WeakHashMap;

public class MainActivity extends AbstractActivityC0165e2 {
...
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        C0055bc c0055bc = new C0055bc(3);
        C0413ku c0413ku = new C0413ku(0, 0, c0055bc);
        int i = AbstractC0915yc.f4104a;
        int i2 = AbstractC0915yc.f4105b;
        C0055bc c0055bc2 = new C0055bc(3);
        C0413ku c0413ku2 = new C0413ku(i, i2, c0055bc2);
        View decorView = getWindow().getDecorView();
        AbstractC0810vi.m433p(decorView, "getDecorView(...)");
        Resources resources = decorView.getResources();
        AbstractC0810vi.m433p(resources, "getResources(...)");
        boolean booleanValue = ((Boolean) c0055bc.mo1039b(resources)).booleanValue();
        Resources resources2 = decorView.getResources();
        AbstractC0810vi.m433p(resources2, "getResources(...)");
        boolean booleanValue2 = ((Boolean) c0055bc2.mo1039b(resources2)).booleanValue();
        ?? obj = new Object();
        Window window = getWindow();
        AbstractC0810vi.m433p(window, "getWindow(...)");
        obj.mo55a(c0413ku, c0413ku2, window, decorView, booleanValue, booleanValue2);
        Window window2 = getWindow();
        AbstractC0810vi.m433p(window2, "getWindow(...)");
        obj.mo1938b(window2);
        setContentView(R.layout.activity_main);
        View findViewById = findViewById(R.id.main);
        C0055bc c0055bc3 = new C0055bc(2);
        WeakHashMap weakHashMap = AbstractC0750tx.f3402a;
        AbstractC0379jx.m1382u(findViewById, c0055bc3);
        this.f1008y = (Button) findViewById(R.id.submitButton);
        this.f1009z = (EditText) findViewById(R.id.flagInput);
        this.f1007A = (TextView) findViewById(R.id.passwordStatus);
        this.f1008y.setOnClickListener(new View$OnClickListenerC0087c8(2, this));
    }
}
```

The `CheckFlag` class reveals an interesting obfuscation technique: Java reflection is used to dynamically invoke the `get_flag()` method from the `Vault` class. This is a common anti-static-analysis technique that makes it harder to trace the code flow during decompilation, as the method calls are resolved at runtime rather than being explicit in the bytecode.

```java
package com.heroctf.freeda1.utils;

import java.lang.reflect.Method;

/* compiled from: r8-map-id-1a9af88ffb3dc84841cff9564d9f010c0ae775e01948d15ad9bf0acf206d5524 */
/* loaded from: classes.dex */
public class CheckFlag {
    public static boolean checkFlag(String str) {
        if (str == null) {
            return false;
        }
        try {
            String str2 = "get_flag";
            Method declaredMethod = Class.forName("com.heroctf.freeda1.utils" + "." + "Vault").getDeclaredMethod(str2, null);
            declaredMethod.setAccessible(true);
            return ((String) declaredMethod.invoke(null, null)).equals(str);
        } catch (Throwable unused) {
            return false;
        }
    }
}
```

The `Vault` class contains the `get_flag()` method that returns the actual flag. However, analyzing this method statically would require significant effort due to potential obfuscation.

```java
package com.heroctf.freeda1.utils;

import java.nio.charset.Charset;

/* compiled from: r8-map-id-1a9af88ffb3dc84841cff9564d9f010c0ae775e01948d15ad9bf0acf206d5524 */
/* loaded from: classes.dex */
final class Vault {

    /* renamed from: a */
    public static final int[] f1010a = {52, 88, 27, 32, 27, 186, 96, 109, 45, 202, 42, 125, 25, 134, 159, 69, 47, 142, 192, 184, 13, 19, 139, 173, 59, 129, 0, 158, 165, 188, 13, 62, 74, 184, 58, 75, 172, 202, 66};

    public static String get_flag() {
        int seed = seed();
        int[] iArr = new int[39];
        for (int i = 0; i < 39; i++) {
            iArr[i] = i;
        }
        int i2 = (-1515870811) ^ seed;
        for (int i3 = 38; i3 >= 0; i3--) {
            int i4 = i2 ^ (i2 << 13);
            int i5 = i4 ^ (i4 >>> 17);
            i2 = i5 ^ (i5 << 5);
            int unsignedLong = (int) (Integer.toUnsignedLong(i2) % (i3 + 1));
            int i6 = iArr[i3];
            iArr[i3] = iArr[unsignedLong];
            iArr[unsignedLong] = i6;
        }
        byte[] bArr = new byte[39];
        for (int i7 = 0; i7 < 39; i7++) {
            int i8 = ((f1010a[iArr[i7]] & 255) - i7) & 255;
            int i9 = (seed >>> 27) & 7;
            bArr[i7] = (byte) ((((i8 << (8 - i9)) | (i8 >>> i9)) & 255) ^ ((seed >>> ((i7 & 3) * 8)) & 255));
        }
        return new String(bArr, Charset.forName("UTF-8"));
    }

    private static int seed() {
        int hashCode = ("com.heroctf.freeda1.MainActivity".hashCode() ^ (-1056969150)) ^ "com.heroctf.freeda1.utils.CheckFlag".hashCode();
        return hashCode ^ (Integer.rotateLeft(hashCode, 7) * (-1640531527));
    }
}
```

A Frida script is developed to hook the Java reflection API (`Method.invoke()`) to intercept calls to `Vault.get_flag()` and capture its return value;

The script specifically monitors reflection calls to detect when `get_flag()` is invoked dynamically, allowing extraction of the flag without needing to understand the internal implementation of the `Vault` class.

```js
function hookGetFlag() {
    var Method = Java.use("java.lang.reflect.Method");

    Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;')
        .implementation = function (receiver, args) {

        if (this.getDeclaringClass().getName() === "com.heroctf.freeda1.utils.Vault" &&
            this.getName() === "get_flag") {

            console.log("[*] Vault.get_flag() called via reflection");

            var result = this.invoke(receiver, args);

            console.log("[*] FLAG =", result);

            return result;
        }

        return this.invoke(receiver, args);
    };
}

Java.perform(function () {
    hookGetFlag();
});

```

Running the Frida script successfully bypasses root detection and intercepts the reflective call to `get_flag()`, revealing the flag:

```shell
$ frida -U -f com.heroctf.freeda1 -l script.js
     ____
    / _  |   Frida 16.7.13 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Pixel 4a (id=)
Spawned `com.heroctf.freeda1`. Resuming main thread!                    
[Pixel 4a::com.heroctf.freeda1 ]-> [*] Vault.get_flag() called via reflection
[*] FLAG = Hero{1_H0P3_Y0U_D1DN'T_S7A71C_4N4LYZ3D}

```

## Flag
`Hero{1_H0P3_Y0U_D1DN'T_S7A71C_4N4LYZ3D}`