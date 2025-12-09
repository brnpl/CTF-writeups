## Overview
This writeup details the reverse engineering of an Android application that requires patching native instructions (in this case x86) at runtime using Frida. The goal is to modify the execution flow of the `getFlag()` function by changing a hardcoded comparison that prevents the flag decryption routine from executing. This challenge demonstrates instruction patching techniques and memory manipulation with Frida.

## Initial analysis
First, the `AndroidManifest.xml` is examined to understand the app structure. Analysis reveals a single `MainActivity`.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="34" android:compileSdkVersionCodename="14" package="com.ad2001.frida0xb" platformBuildVersionCode="34" platformBuildVersionName="14">
    <uses-sdk android:minSdkVersion="29" android:targetSdkVersion="34"/>
    <permission android:name="com.ad2001.frida0xb.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature"/>
    <uses-permission android:name="com.ad2001.frida0xb.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application android:theme="@style/Theme.Frida0xB" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:extractNativeLibs="false" android:fullBackupContent="@xml/backup_rules" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules">
        <activity android:name="com.ad2001.frida0xb.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <provider android:name="androidx.startup.InitializationProvider" android:exported="false" android:authorities="com.ad2001.frida0xb.androidx-startup">
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
Next, the APK is decompiled with `jadx-gui` to examine `MainActivity.java`. The `MainActivity` loads a native library called `frida0xb` and declares a JNI method `getFlag()`. The native library is loaded using `System.loadLibrary("frida0xb")` in the static initializer.

The decompiled code shows a simple button click handler that calls the native `getFlag()` method.

```java
package com.ad2001.frida0xb;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.ad2001.frida0xb.databinding.ActivityMainBinding;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MainActivity.kt */
/* loaded from: classes3.dex */
public final class MainActivity extends AppCompatActivity {
    public static final Companion Companion = new Companion(null);
    private ActivityMainBinding binding;

    static {
        System.loadLibrary("frida0xb");
    }

    public final native void getFlag();

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        Intrinsics.checkNotNullExpressionValue(inflate, "inflate(layoutInflater)");
        this.binding = inflate;
        if (inflate == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            inflate = null;
        }
        setContentView(inflate.getRoot());
        View findViewById = findViewById(C0567R.C0570id.button);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(R.id.button)");
        Button btn = (Button) findViewById;
        btn.setOnClickListener(new View.OnClickListener() { // from class: com.ad2001.frida0xb.MainActivity$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.onCreate$lambda$0(MainActivity.this, view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onCreate$lambda$0(MainActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getFlag();
    }

...
```

## Native library analysis
Ghidra is used to disassemble and decompile the `libfrida0xb.so` library. The JNI function `Java_com_ad2001_frida0xb_MainActivity_getFlag` implements the flag decryption logic, but it's protected by an impossible condition.

The function contains a complete flag decryption routine that XORs each character of the encrypted string with 0x2c and logs the result. However, the `if (false)` condition prevents this code from ever executing.

**Note:** If Ghidra doesn't show any code, disable "Eliminate Unreachable Code" in "Edit -> Tool Options -> Decompiler -> Analysis" to see the full decompiled output.

```c
void Java_com_ad2001_frida0xb_MainActivity_getFlag(void)

{
  uint uVar1;
  void *pvVar2;
  uint local_18;
  
  if (false) {
    uVar1 = __strlen_chk("j~ehmWbmxezisdmogi~Q",0xffffffff);
    pvVar2 = operator.new[](uVar1 + 1);
    for (local_18 = 0; local_18 < uVar1; local_18 = local_18 + 1) {
      *(byte *)((int)pvVar2 + local_18) = "j~ehmWbmxezisdmogi~Q"[local_18] ^ 0x2c;
    }
    *(undefined *)((int)pvVar2 + local_18) = 0;
    __android_log_print(3,"FLAG :",&DAT_0001687e,pvVar2);
    if (pvVar2 != (void *)0x0) {
      operator.delete[](pvVar2);
    }
  }
  return;
}
```

Here's the same code with improved variable names for clarity:

```c
void Java_com_ad2001_frida0xb_MainActivity_getFlag(void)

{
  uint len_flag;
  void *flag;
  uint i;
  
  if (false) {
    len_flag = __strlen_chk("j~ehmWbmxezisdmogi~Q",0xffffffff);
    flag = operator.new[](len_flag + 1);
    for (i = 0; i < len_flag; i = i + 1) {
      *(byte *)((int)flag + i) = "j~ehmWbmxezisdmogi~Q"[i] ^ 0x2c;
    }
    *(undefined *)((int)flag + i) = 0;
    __android_log_print(3,"FLAG :",&DAT_0001687e,flag);
    if (flag != (void *)0x0) {
      operator.delete[](flag);
    }
  }
  return;
}
```

Looking at the x86 assembly reveals what the `if (false)` actually means; it's a comparison with `0xdeadbeef` and `0x539`:
```assembly
# start of function
00020e00 55              PUSH       EBP
00020e01 89 e5           MOV        EBP,ESP
00020e03 53              PUSH       EBX
00020e04 83 ec 34        SUB        ESP,0x34
00020e07 e8 00 00        CALL       LAB_00020e0c
         00 00
                     LAB_00020e0c                                    XREF[1]:     00020e07(j)  
00020e0c 58              POP        EAX
00020e0d 81 c0 7c        ADD        EAX,0x1f77c
         f7 01 00
00020e13 89 45 dc        MOV        dword ptr [EBP + local_28],EAX=>__DT_PLTGOT      = 00040460
00020e16 8b 45 0c        MOV        EAX,dword ptr [EBP + param_2]
00020e19 8b 45 08        MOV        EAX,dword ptr [EBP + param_1]

# move 0xdeadbeef, compare to 0x539, jump if not equal
00020e1c c7 45 f0        MOV        dword ptr [EBP + local_14],0xdeadbeef
         ef be ad de
00020e23 81 7d f0        CMP        dword ptr [EBP + local_14],0x539
         39 05 00 00
00020e2a 0f 85 d8        JNZ        LAB_00020f08
         00 00 00
```

## Memory Patching
There are several ways to execute the flag decryption code. 

In this example, we focus on patching the MOV instruction:
```
Change the immediate value from `0xdeadbeef` to '0x539'
Original: c7 45 f0 ef be ad de (MOV [EBP-0x10], 0xdeadbeef)
Patched:  c7 45 f0 39 05 00 00 (MOV [EBP-0x10], 0x539)
Result: Comparison succeeds, JNZ doesn't jump
```

### Patch the MOV instruction
This script patches the native function `getFlag()` by replacing the hard-coded value `0xdeadbeef` with `0x539`. Specifically, it overwrites the MOV instruction at offset `0x1C`, which sets the value stored in `[EBP + local_14]`.

```js
setTimeout(function () {
    var addr = Module.findExportByName("libfrida0xb.so", 
        "Java_com_ad2001_frida0xb_MainActivity_getFlag");
    
    console.log("[*] getFlag address:", addr);

    // based on ghidra, the offset of the MOV instruction that sets 0xdeadbeef is 0x1c
    // function getFlag:
    // 00020e00 55              PUSH       EBP
    // 00020e01 89 e5           MOV        EBP,ESP
    // 00020e03 53              PUSH       EBX
    // 00020e04 83 ec 34        SUB        ESP,0x34
    // 00020e07 e8 00 00        CALL       LAB_00020e0c
    //          00 00
    //                      LAB_00020e0c                                    XREF[1]:     00020e07(j)  
    // 00020e0c 58              POP        EAX
    // 00020e0d 81 c0 7c        ADD        EAX,0x1f77c
    //          f7 01 00
    // 00020e13 89 45 dc        MOV        dword ptr [EBP + local_28],EAX=>__DT_PLTGOT      = 00040460
    // 00020e16 8b 45 0c        MOV        EAX,dword ptr [EBP + param_2]
    // 00020e19 8b 45 08        MOV        EAX,dword ptr [EBP + param_1]
    //
    // from here:
    // 00020e1c c7 45 f0        MOV        dword ptr [EBP + local_14],0xdeadbeef
    //          ef be ad de

    var mov_instruction_offset = 0x1c;
    var mov_addr = addr.add(mov_instruction_offset);
    
    console.log("[*] target MOV instruction at:", mov_addr);
    
    // patch the instruction to change 0xdeadbeef to 0x539
    console.log("[*] patching instruction...");
    
    Memory.patchCode(mov_addr, 7, function (code) {
        const cw = new X86Writer(code, {pc: mov_addr});
        
        // write the patched MOV instruction
        // MOV dword ptr [EBP-0x10], 0x539
        // opcode: c7 45 f0 39 05 00 00
        cw.putBytes([0xc7, 0x45, 0xf0, 0x39, 0x05, 0x00, 0x00]);
        cw.flush();
    });
    
    // verify the patch
    var patched = Memory.readByteArray(mov_addr, 7);
    console.log("[*] patched instruction bytes:");
    console.log(hexdump(patched, { length: 7, ansi: true }));
    console.log("[*] instruction: MOV dword ptr [EBP-0x10], 0x00000539");
    
}, 1000);
```


The patch successfully changes the immediate value from `0xdeadbeef` to `0x539`:
```
from:
MOV dword ptr [EBP-0x10], 0xdeadbeef   ; 7 bytes
  c7 45 f0        - Opcode and addressing (3 bytes)
  ef be ad de     - Immediate value (4 bytes)

to:
from:
MOV dword ptr [EBP-0x10], 0x00000539   ; 7 bytes
  c7 45 f0        - Opcode and addressing (3 bytes)
  39 05 00 00     - Immediate value (4 bytes)
```

When the comparison executes, it finds `0x539 == 0x539`, causing the JNZ to not branch, allowing execution to fall through to the flag decryption code.

```shell
$ frida -U -f com.ad2001.frida0xb -l script.js 
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
Spawned `com.ad2001.frida0xb`. Resuming main thread!                    
[Nexus 4::com.ad2001.frida0xb ]-> [*] getFlag address: 0xbad54e00
[*] target MOV instruction at: 0xbad54e1c
[*] patching instruction...
[*] patched instruction bytes:
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  c7 45 f0 39 05 00 00                             .E.9...
[*] instruction: MOV dword ptr [EBP-0x10], 0x00000539

$ adb logcat | grep 'FLAG'
12-06 09:21:41.926  9261  9261 D FLAG :  : FRIDA{NATIVE_HACKER}
```

## Flag
FRIDA{NATIVE_LAND}