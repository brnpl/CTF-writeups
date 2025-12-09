## Overview
This writeup details the reverse engineering of an Android application that requires calling a hidden native function. The goal is to reverse engineer the native library to find and invoke the `get_flag()` function using Frida.

## Initial analysis
First, the `AndroidManifest.xml` is examined to understand the app structure. Analysis reveals a single `MainActivity`.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="34" android:compileSdkVersionCodename="14" package="com.ad2001.frida0xa" platformBuildVersionCode="34" platformBuildVersionName="14">
    <uses-sdk android:minSdkVersion="29" android:targetSdkVersion="34"/>
    <permission android:name="com.ad2001.frida0xa.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature"/>
    <uses-permission android:name="com.ad2001.frida0xa.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application android:theme="@style/Theme.Frida0xA" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:extractNativeLibs="false" android:fullBackupContent="@xml/backup_rules" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules">
        <activity android:name="com.ad2001.frida0xa.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <provider android:name="androidx.startup.InitializationProvider" android:exported="false" android:authorities="com.ad2001.frida0xa.androidx-startup">
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
Next, the APK is decompiled with `jadx-gui` to examine `MainActivity.java`. The `MainActivity` loads a native library called `frida0xa` and calls a JNI method `stringFromJNI()`. The native library is loaded using `System.loadLibrary("frida0xa")` in the static initializer.

```java
package com.ad2001.frida0xa;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.ad2001.frida0xa.databinding.ActivityMainBinding;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MainActivity.kt */
public final class MainActivity extends AppCompatActivity {
    public static final Companion Companion = new Companion(null);
    private ActivityMainBinding binding;

    public final native String stringFromJNI();

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        Intrinsics.checkNotNullExpressionValue(inflate, "inflate(layoutInflater)");
        this.binding = inflate;
        ActivityMainBinding activityMainBinding = null;
        if (inflate == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            inflate = null;
        }
        setContentView(inflate.getRoot());
        ActivityMainBinding activityMainBinding2 = this.binding;
        if (activityMainBinding2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
        } else {
            activityMainBinding = activityMainBinding2;
        }
        activityMainBinding.sampleText.setText(stringFromJNI());
    }

    /* compiled from: MainActivity.kt */
    /* loaded from: classes4.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    static {
        System.loadLibrary("frida0xa");
    }
}
```

## Native library analysis
`Ghidra` is used to disassemble and decompile the `libfrida0xa.so` library. 

The main JNI function is `Java_com_ad2001_frida0xa_MainActivity_stringFromJNI` and its signature follows the JNI naming convention: `Java_<package>_<class>_<method>`. This function creates a C++ `std::string` containing `Hello Hackers`, converts it to a C-style string, and then uses `NewStringUTF()` (variable `uVar3`) to create a Java String object that's returned to the calling Java code.

```c

undefined8 Java_com_ad2001_frida0xa_MainActivity_stringFromJNI(_JNIEnv *param_1)

{
  long lVar1;
  char *pcVar2;
  undefined8 uVar3;
  basic_string<> abStack_30 [24];
  long local_18;
  
  lVar1 = tpidr_el0;
  local_18 = *(long *)(lVar1 + 0x28);
  std::__ndk1::basic_string<>::basic_string<>(abStack_30,"Hello Hackers");
  pcVar2 = (char *)FUN_0011dd3c(abStack_30);
                    /* try { // try from 0011dc2c to 0011dc2f has its CatchHandler @ 0011dc68 */
  uVar3 = _JNIEnv::NewStringUTF(param_1,pcVar2);
  std::__ndk1::basic_string<>::~basic_string(abStack_30);
  lVar1 = tpidr_el0;
  if (*(long *)(lVar1 + 0x28) == local_18) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

This is the raw decompiled output from `Ghidra` for the hidden `get_flag()` function.

```c
/* get_flag(int, int) */

void get_flag(int param_1,int param_2)

{
  long lVar1;
  ulong uVar2;
  int local_54;
  char acStack_2c [19];
  undefined local_19;
  long local_18;
  
  lVar1 = tpidr_el0;
  local_18 = *(long *)(lVar1 + 0x28);
  if (param_1 + param_2 == 3) {
    local_54 = 0;
    while( true ) {
      uVar2 = __strlen_chk("FPE>9q8A>BK-)20A-#Y",0xffffffffffffffff);
      if (uVar2 <= (ulong)(long)local_54) break;
      acStack_2c[local_54] = "FPE>9q8A>BK-)20A-#Y"[local_54] + (char)local_54 * '\x02';
      local_54 = local_54 + 1;
    }
    local_19 = 0;
    __android_log_print(3,&DAT_00113624,"Decrypted Flag: %s",acStack_2c);
  }
  lVar1 = tpidr_el0;
  if (*(long *)(lVar1 + 0x28) == local_18) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

The following snippets shows the same function with improved variable names for readability.

`idx` is simply the loop counter, and `flag` is the 19‑byte buffer that stores the decrypted output. The call to `__android_log_print()` writes the final string to Android’s logcat.

The decryption routine iterates over each character in the encrypted string and transforms it by adding (`2 * idx`) to its ASCII value. 
```
'F' (70) at index 0 → 70 + 0 = 70 → 'F'
'P' (80) at index 1 → 80 + 2 = 82 → 'R'
...
```

```c
/* get_flag(int, int) */

void get_flag(int param_1,int param_2)

{
  long lVar1;
  ulong uVar2;
  int idx;
  char flag [19];
  undefined local_19;
  long local_18;
  
  lVar1 = tpidr_el0;
  local_18 = *(long *)(lVar1 + 0x28);

  if (param_1 + param_2 == 3) {
    idx = 0;
    while( true ) {
      uVar2 = __strlen_chk("FPE>9q8A>BK-)20A-#Y",0xffffffffffffffff);
      if (uVar2 <= (ulong)(long)idx) break;
      flag[idx] = "FPE>9q8A>BK-)20A-#Y"[idx] + (char)idx * '\x02';
      idx = idx + 1;
    }
    local_19 = 0;

    // print flag in android logs
    __android_log_print(3,&DAT_00113624,"Decrypted Flag: %s",flag);
  }

  // stack canary protection
  lVar1 = tpidr_el0;
  if (*(long *)(lVar1 + 0x28) == local_18) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

This interactive Frida REPL session demonstrates reconnaissance of the target process. 

The first command enumerates all loaded modules and filters for those containing `lib`. The second command uses `Module.enumerateExports()` to list all exported symbols from `libfrida0xa.so` that contain the string `flag`. This discovers the mangled function name `_Z8get_flagii`. The mangling follows the Itanium C++ ABI: `_Z` indicates name mangling, `8` is the length of the function name `get_flag`, and `ii` indicates two integer parameters. This exported symbol is the key to calling the hidden function, even though it's never invoked by the app's normal execution flow.

```shell
[Nexus 4::com.ad2001.frida0xa ]-> Process.enumerateModules().map(m => m.name).filter(n => n.includes("lib"));
[
    "libandroid_runtime.so",
...
    "libEGL_emulation.so",
    "libfrida0xa.so",
    "libGLESv1_CM_emulation.so",
    "libGLESv2_emulation.so"
]
[Nexus 4::com.ad2001.frida0xa ]-> Module.enumerateExports("libfrida0xa.so").filter(e => e.name.includes("flag"));
[
    {
        "address": "0xbb460bb0",
        "name": "_Z8get_flagii", (8=lenght func name, ii=takes two int)
        "type": "function"
    }
]
```

This exploit script demonstrates how to invoke the hidden native function. 

The `setTimeout()` delays execution by 1 second to ensure the app is fully loaded. `Module.findExportByName()` locates the `_Z8get_flagii` symbol in memory and returns its runtime address. 

The `NativeFunction` constructor creates a JavaScript wrapper around the native function, specifying its return type (void) and parameter types (["int", "int"]). 

Finally, `get_flag(1, 2)` invokes the native function with arguments that satisfy the condition `1 + 2 == 3`, triggering the decryption routine.

```js
setTimeout(function () {

    var addr = Module.findExportByName("libfrida0xa.so", "_Z8get_flagii");
    console.log("[*] address of get_flag(): ", addr);

    var get_flag = new NativeFunction(addr, "void", ["int", "int"]);

    console.log("[*] calling get_flag(1,2)...");
    get_flag(1, 2);

}, 1000);

```

The output confirms it found the function at address `0xbb494bb0` and the call to `get_flag(1,2)` was executed successfully. 

The second command uses `adb logcat` piped through grep to filter Android's system logs for `decrypt` (have a look at the `get_flag()` source code).

```shell
$ frida -U -f com.ad2001.frida0xa -l script.js
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
   . . . .   Connected to Nexus 4 (id=)
Spawned `com.ad2001.frida0xa`. Resuming main thread!                    
[Nexus 4::com.ad2001.frida0xa ]-> [*] address of get_flag():  0xbb494bb0
[*] calling get_flag(1,2)...
[Nexus 4::com.ad2001.frida0xa ]->                

$ adb logcat  | grep -i "decrypt" 
12-06 07:20:02.863  6512  6535 D FLAG    : Decrypted Flag: FRIDA{DONT_CALL_ME}
```

## Flag
FRIDA{DONT_CALL_ME}