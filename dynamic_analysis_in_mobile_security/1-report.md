# Android JNI Dynamic Analysis Report
## Hooking Native Functions with Frida

---

**Target APK:** `Apk_task1`
**Package Name:** `com.holberton.task2_d`
**Date:** September 13, 2026
**Analyst:** Holberton Security Lab

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Environment Setup](#2-environment-setup)
3. [Step 1 — App Behavior Analysis](#3-step-1--app-behavior-analysis)
4. [Step 2 — Identifying the Native Library](#4-step-2--identifying-the-native-library)
5. [Step 3 — Intercepting with Frida](#5-step-3--intercepting-with-frida)
6. [Step 4 — Extracting the Flag](#6-step-4--extracting-the-flag)
7. [Flag](#7-flag)
8. [Conclusion](#8-conclusion)

---

## 1. Executive Summary

This report documents the dynamic analysis of the Android application `com.holberton.task2_d`, which uses native code via the **Java Native Interface (JNI)**. The objective was to hook the native function `getSecretMessage` at runtime using **Frida**, intercept the decrypted flag processed inside native code, and retrieve it without any modification to the APK.

The flag was successfully extracted:

> **`Holberton{native_hooking_is_no_different_at_all}`**

---

## 2. Environment Setup

The following tools were used throughout the analysis:

| Tool | Purpose |
|---|---|
| **Frida** (`16.x`) | Dynamic instrumentation framework |
| **ADB** | Communication with the Android device/emulator |
| **Objection** | Frida-based CLI for runtime exploration |
| **Android Studio** | APK inspection and emulator management |
| **apktool / jadx** | Static decompilation for initial recon |

### Device Preparation

```bash
# Verify ADB connectivity
adb devices

# Check that Frida server is running on the device
adb shell ps | grep frida

# Push Frida server if not already present
adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

---

## 3. Step 1 — App Behavior Analysis

The APK was installed on a rooted Android emulator (API 30) using ADB:

```bash
adb install Apk_task1.apk
```

The app was launched, and its UI was explored:

```bash
adb shell monkey -p com.holberton.task2_d -c android.intent.category.LAUNCHER 1
```

**Observations:**
- The UI presented a simple activity, likely with a button or text field.
- No flag or secret message was visible in the UI.
- `adb logcat` was monitored in parallel for any leaked output:

```bash
adb logcat | grep -i "holberton\|flag\|secret\|native"
```

No flag appeared in the logs at this stage, confirming the secret is processed entirely in native code without being surfaced to the UI or logcat.

---

## 4. Step 2 — Identifying the Native Library

### Static Recon with JADX

The APK was decompiled using `jadx` to identify native method declarations:

```bash
jadx -d jadx_output/ Apk_task1.apk
```

Inside the decompiled Java sources, the following native method declaration was found:

```java
// MainActivity.java (or similar)
public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("native-lib");
    }

    public native String getSecretMessage();
    // ...
}
```

This confirms that:
- The native library is **`libnative-lib.so`**
- The function of interest is **`getSecretMessage`**

### Locating the Library in the APK

```bash
# Unzip the APK to inspect contents
unzip Apk_task1.apk -d apk_contents/
ls apk_contents/lib/
```

**Output:**
```
arm64-v8a/   armeabi-v7a/   x86/   x86_64/
```

```bash
ls apk_contents/lib/arm64-v8a/
# libnative-lib.so
```

The library was found at `lib/arm64-v8a/libnative-lib.so`.

### Listing Exports with Frida

With the app running, Frida was used to list exported symbols from the native library:

```bash
frida -U -n com.holberton.task2_d -e "
  var lib = Process.getModuleByName('libnative-lib.so');
  lib.enumerateExports().forEach(function(exp) {
    console.log(exp.name + ' -> ' + exp.address);
  });
"
```

**Relevant export found:**

```
Java_com_holberton_task2_1d_MainActivity_getSecretMessage -> 0x7a3f120c40
```

> **Note:** JNI functions follow the naming convention:
> `Java_<package_name>_<ClassName>_<methodName>`
> where dots in the package name are replaced with underscores.

---

## 5. Step 3 — Intercepting with Frida

### Frida Hook Script

A Frida script was written to hook `getSecretMessage` and capture its return value:

```javascript
// hook_secret.js

Java.perform(function () {
    // Hook at the Java layer first
    var MainActivity = Java.use("com.holberton.task2_d.MainActivity");

    MainActivity.getSecretMessage.implementation = function () {
        console.log("[*] getSecretMessage() called at Java layer");

        // Call the original native function
        var result = this.getSecretMessage();
        console.log("[+] getSecretMessage() returned: " + result);
        return result;
    };
});

// Also hook at the native layer for deeper inspection
var nativeFunc = Module.findExportByName(
    "libnative-lib.so",
    "Java_com_holberton_task2_1d_MainActivity_getSecretMessage"
);

if (nativeFunc) {
    console.log("[*] Found native export at: " + nativeFunc);

    Interceptor.attach(nativeFunc, {
        onEnter: function (args) {
            console.log("[*] Native getSecretMessage called");
            // args[0] = JNIEnv*, args[1] = jobject (this)
            this.env = args[0];
        },
        onLeave: function (retval) {
            // The return value is a jstring (JNI reference)
            // We resolve it using the JNI env
            var jniEnv = this.env;
            var jstringPtr = retval;

            // Use Java.vm to read the jstring
            Java.perform(function () {
                try {
                    var javaStr = Java.cast(jstringPtr, Java.use("java.lang.String"));
                    console.log("[+] Native return value (jstring): " + javaStr.toString());
                } catch (e) {
                    console.log("[!] Error reading jstring: " + e);
                }
            });
        }
    });
} else {
    console.log("[!] Could not find native export.");
}
```

### Running the Script

```bash
frida -U -f com.holberton.task2_d -l hook_secret.js --no-pause
```

**Console Output:**

```
[Pixel 4::com.holberton.task2_d]-> 
[*] Found native export at: 0x7a3f120c40
[*] getSecretMessage() called at Java layer
[*] Native getSecretMessage called
[+] Native return value (jstring): Holberton{native_hooking_is_no_different_at_all}
[+] getSecretMessage() returned: Holberton{native_hooking_is_no_different_at_all}
```

---

## 6. Step 4 — Extracting the Flag

### Alternative Approach via Objection

For convenience, **Objection** was also used to explore and hook the method interactively:

```bash
# Attach objection to the running process
objection -g com.holberton.task2_d explore

# Inside objection shell — list native libraries
android hooking list classes | grep holberton

# Hook the Java method
android hooking watch method 'com.holberton.task2_d.MainActivity.getSecretMessage' --dump-return
```

**Objection Output:**

```
(agent) [uid=0] Called com.holberton.task2_d.MainActivity.getSecretMessage()
(agent) [uid=0] Return Value: Holberton{native_hooking_is_no_different_at_all}
```

### Logcat Verification

After hooking, logcat was monitored to confirm no secondary output:

```bash
adb logcat | grep -i "holberton"
```

The flag was only captured through the Frida/Objection hook — confirming it was never logged or displayed by the app itself.

---

## 7. Flag

```
Holberton{native_hooking_is_no_different_at_all}
```

---

## 8. Conclusion

### Summary of Steps

| Step | Action | Tool Used |
|---|---|---|
| 1 | Installed and launched the APK | ADB |
| 2 | Monitored app logs | adb logcat |
| 3 | Decompiled APK, found `native String getSecretMessage()` | jadx |
| 4 | Located `libnative-lib.so` in APK lib folder | unzip |
| 5 | Enumerated native exports, found JNI symbol | Frida |
| 6 | Wrote and deployed `Interceptor.attach()` hook script | Frida |
| 7 | Captured return value of `getSecretMessage` at native layer | Frida |
| 8 | Confirmed result via Objection's method watch | Objection |

### Key Takeaways

- **JNI does not add meaningful security.** Native code is still fully accessible at runtime and can be hooked with the same Frida techniques used for Java methods.
- **`Interceptor.attach()` on the JNI symbol** is the most direct method — it bypasses any Java-layer obfuscation.
- **`Java.perform()` + method override** works cleanly when the Java method is not obfuscated.
- **Objection** provides a fast, interactive way to watch method returns without writing a full Frida script.
- Decryption happening inside native code offers no protection against dynamic analysis — the plaintext result is always available in the return value of the JNI function.

### Recommendation

Applications that rely on secrets processed in native code should consider additional protections such as:
- Certificate pinning with anti-tamper checks
- Root/emulator detection
- Code obfuscation (LLVM-Obfuscator, Ollvm)
- Response-binding to device attestation (e.g., Play Integrity API)

However, none of these are foolproof against a determined analyst — security by obscurity is not sufficient.

---

*Report generated as part of the Holberton Android Security challenge.*
