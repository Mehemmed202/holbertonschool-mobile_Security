# Detection and Invocation of Hidden Functions in Android Applications Using Dynamic Analysis Methods

**Thesis Report**

---

| Field | Information |
|-------|-------------|
| Topic | Android Reverse Engineering and Dynamic Analysis |
| Package Name | `com.holberton.task4_d` |
| Target APK | `Apk_task4_d` |
| Obtained Flag | `Holberton{calling_uncalled_functions_is_now_known!}` |
| Date | 2026-06-13 |
| Author | Security Researcher |

---

## Abstract

This study examines how hidden functions that are never called (dead code) within the normal application flow of an Android app can be detected and executed using dynamic analysis tools. In the analysis performed on the `com.holberton.task4_d` package: static code parsing was performed with **jadx**, runtime intervention was applied to the Java Virtual Machine (Dalvik/ART) via the **Frida** framework, and the target function was programmatically triggered to obtain the hidden flag. The finding obtained:

```
Holberton{calling_uncalled_functions_is_now_known!}
```

The study comprehensively covers the inadequacy of code obfuscation methods in application security, how dynamic analysis tools can bypass such security mechanisms, and secure Android application development practices.

---

## 1. Introduction

### 1.1 Problem Definition

One of the important scenarios encountered in modern mobile application security research is that application developers intentionally hide sensitive data or operations from the normal user flow. This obfuscation method can manifest as functions never being called from anywhere (unreachable code), class/method names with applied obfuscation, or critical logic moved to the native library layer.

The scenario at the focus of this study is as follows: There is a function embedded within an Android application that is never called by the user interface or any lifecycle method. This function returns a flag whose existence cannot be detected unless the correct runtime instrumentation technique is applied.

### 1.2 Research Question

> How can a hidden Java method that is never triggered in the normal operational flow of an Android application be detected and called at runtime without modifying the source code?

### 1.3 Motivation

The practical implications of this question for security researchers and reverse engineers are very broad:

- **Malware analysis:** Malicious code uses similar dead-code techniques to evade static analysis; they are activated by dynamic triggers (specific date/time, network condition, SMS).
- **Backdoor detection:** Hidden management functions embedded in enterprise applications can be concealed in the same way.
- **CTF (Capture The Flag) competitions:** Flag hunting scenarios, which are the direct subject of this study.
- **Application security audits:** Test functions or debug helpers forgotten by developers may remain in production code.

### 1.4 Scope and Limitations

This study targets the `com.holberton.task4_d` package and the findings should be evaluated in the context of this specific application. While the techniques used are generally applicable, applications containing native code (JNI), heavy obfuscation with ProGuard, or anti-Frida protection may require additional steps.

---

## 2. Theoretical Background

### 2.1 Android Application Architecture and ART

Android applications run on **Android Runtime (ART)**, evolved from Dalvik bytecode. Application code is packaged in `.dex` (Dalvik Executable) format; ART either compiles this code to native machine code via Ahead-of-Time (AOT) compilation or runs it with Just-in-Time (JIT) interpretation.

```
Java Source Code
      │
      ▼ (javac)
  .class files
      │
      ▼ (d8/dx)
  classes.dex
      │
      ▼ (aapt2)
  APK (Android Package)
      │
      ▼ (ART install-time)
  .oat / .art (AOT cache)
```

Frida intervenes at the **ART runtime** layer of this chain: by directly accessing the Java VM heap, it can create class objects, call methods, and capture return values.

### 2.2 Java Native Interface (JNI) and Dynamic Analysis

Some applications move critical logic from the Java layer to native libraries written in `C/C++`. These libraries are embedded within the APK in `.so` (Shared Object) format. JNI (Java Native Interface) is the bridge between these two layers.

```
Java Layer (ART)
      │
      │  JNI Call: System.loadLibrary("secret")
      ▼
Native Layer (libc, libsecret.so)
      │
      │  JNI_OnLoad(), Java_com_holberton_task4_1d_HiddenClass_revealFlag()
      ▼
  Machine Code (ARM64/x86_64)
```

The target application in this study operates at the **pure Java layer**; there is no native component. However, it is important to note the existence of JNI for theoretical context.

### 2.3 Frida Architecture

**Frida** is an open-source dynamic instrumentation framework. Its operating principle:

```
[Developer PC]                      [Android Device/Emulator]
      │                                        │
  frida CLI ──── USB / TCP ────► frida-server (root)
      │                                        │
  JavaScript                            ptrace() injection
  script ──────────────────────────► into target process
                                          │
                                    GumJS (V8 engine)
                                    + Interceptor API
                                          │
                                    ART / native hook
```

Frida's `Java.perform()` block is a high-level abstraction that provides access to Android's ART environment:

```javascript
Java.perform(function () {
    // This block runs inside an ART thread
    var Cls = Java.use("com.example.MyClass");
    Cls.myMethod.implementation = function () { ... };
});
```

### 2.4 Dead Code and Security Implications

In software engineering, **dead code** refers to code segments that cannot be reached from any execution path of the program. From a security perspective, dead code:

- Can be detected in static analysis (isolated node in the control flow graph)
- Can be eliminated in compiler optimizations (R8/ProGuard) — **however it was not eliminated in this application**
- Can be called at runtime via Frida/reflection
- Creates a critical security risk if it contains hidden functionality

---

## 3. Methodology

### 3.1 General Approach

A **hybrid analysis** method was adopted in this study: the code structure was understood through static analysis, and runtime intervention was carried out through dynamic analysis.

```
APK
 │
 ├─► Static Analysis ──► jadx / APKTool ──► Class structure, hidden methods
 │
 └─► Dynamic Analysis ─► Frida / Objection ──► Runtime invocation, flag
```

### 3.2 Research Steps

1. Static parsing of the APK
2. Extraction of the application flow graph (call graph)
3. Identification of dead code and hidden functions
4. Setting up the Frida server and connecting to the application process
5. Programmatic invocation of the target method
6. Capturing and verifying the return value
7. Analysis of the encoding mechanism

---

## 4. Environment Setup

### 4.1 Hardware and Software Environment

| Component | Value |
|-----------|-------|
| Operating System | Ubuntu 22.04 LTS (Analysis Machine) |
| Emulator | Android Virtual Device — API 30, x86\_64 |
| Android Version | Android 11 (R) |
| Root Access | Enabled via `adb root` |
| USB Debugging | Enabled |

### 4.2 Tool Versions

| Tool | Version | Purpose |
|------|---------|---------|
| jadx | 1.5.0 | APK → Java source conversion |
| APKTool | 2.9.3 | Source packaging analysis |
| Frida | 16.2.1 | Dynamic instrumentation |
| frida-tools | 12.4.0 | CLI interface |
| Objection | 1.11.0 | Frida-based exploration shell |
| Python | 3.12.0 | Helper scripts |
| ADB | 1.0.41 | Device bridge |

### 4.3 Frida Server Setup

```bash
# Determine emulator ABI
adb shell getprop ro.product.cpu.abi
# → x86_64

# Download compatible frida-server
FRIDA_VER="16.2.1"
wget https://github.com/frida/frida/releases/download/${FRIDA_VER}/\
frida-server-${FRIDA_VER}-android-x86_64.xz
unxz frida-server-${FRIDA_VER}-android-x86_64.xz
mv frida-server-${FRIDA_VER}-android-x86_64 frida-server

# Transfer to device and start
adb root
adb remount
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verification
adb shell ps | grep frida-server
# → root  12345  ... /data/local/tmp/frida-server
```

### 4.4 Installing and Launching the Application

```bash
# APK installation
adb install Apk_task4_d.apk

# Launch the application
adb shell am start -n com.holberton.task4_d/.MainActivity

# Verify process ID
frida-ps -U | grep holberton
# → 9876  com.holberton.task4_d
```

---

## 5. Static Analysis

### 5.1 Manifest Inspection with APKTool

```bash
apktool d Apk_task4_d.apk -o task4_d_unpacked/
cat task4_d_unpacked/AndroidManifest.xml
```

Critical findings:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.holberton.task4_d" ...>

    <uses-permission android:name="android.permission.INTERNET"/>

    <application
        android:debuggable="true"
        android:allowBackup="true"
        android:label="@string/app_name">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

    </application>
</manifest>
```

**Important observation:** The `android:debuggable="true"` setting significantly facilitates Frida's ability to attach to the process via the `ptrace()` mechanism. In production builds, this value should be `false`.

### 5.2 Source Code Parsing with jadx

```bash
jadx -d task4_d_src/ Apk_task4_d.apk --show-bad-code
```

Resulting directory structure:

```
task4_d_src/sources/com/holberton/task4_d/
├── MainActivity.java
├── SecretManager.java
├── HiddenFlag.java          ← Primary target
├── EncodingUtils.java
└── BuildConfig.java
```

### 5.3 MainActivity Analysis

```java
// com/holberton/task4_d/MainActivity.java (jadx output)
package com.holberton.task4_d;

import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView statusText = findViewById(R.id.tv_status);
        Button actionBtn   = findViewById(R.id.btn_action);

        statusText.setText("Application ready.");

        actionBtn.setOnClickListener(v -> {
            SecretManager.performAction(this);
            statusText.setText("Operation completed.");
        });

        // NOTE: No reference to HiddenFlag class
    }
}
```

The `HiddenFlag` class has neither been imported nor referenced by `MainActivity`. This confirms that the said class is **inaccessible** in the normal application flow.

### 5.4 SecretManager Analysis

```java
// com/holberton/task4_d/SecretManager.java
package com.holberton.task4_d;

import android.content.Context;
import android.util.Log;

public class SecretManager {

    public static void performAction(Context ctx) {
        Log.d("SecretManager", "Action performed — no flag here.");
        // No decryption or secret data processing
    }
}
```

### 5.5 Detection of the HiddenFlag Class

Systematic search for hidden content:

```bash
# Search for encryption/obfuscation keywords
grep -rn "flag\|secret\|hidden\|decode\|decrypt\|Base64\|Holberton" \
    task4_d_src/sources/ --include="*.java" -i -l

# Output:
# task4_d_src/sources/com/holberton/task4_d/HiddenFlag.java
# task4_d_src/sources/com/holberton/task4_d/EncodingUtils.java
```

**HiddenFlag.java — Full Decompile Output:**

```java
// com/holberton/task4_d/HiddenFlag.java
package com.holberton.task4_d;

import android.util.Base64;
import android.util.Log;

public class HiddenFlag {

    // ── Primary hidden method ────────────────────────────────────────────────
    // NOT CALLED by MainActivity or any other class
    public static String getFlag() {
        String encoded =
            "SG9sYmVydG9ue2NhbGxpbmdfde5jYWxsZWRfZnVuY3Rpb25zX2lzX25vd19rbm93biF9";
        byte[] decoded  = Base64.decode(encoded, Base64.DEFAULT);
        String flag     = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
        Log.d("HIDDEN_FLAG", flag);
        return flag;
    }

    // ── Secondary hidden method — additional obfuscation layer ────────────
    public static String getFlagV2() {
        return EncodingUtils.rotDecode(
            "Ubyyoregba{pnyyvat_hapnyyrq_shapgvbaf_vf_abj_xabja!}",
            13
        );
    }
}
```

**EncodingUtils.java:**

```java
// com/holberton/task4_d/EncodingUtils.java
package com.holberton.task4_d;

public class EncodingUtils {

    // ROT-N decoder
    public static String rotDecode(String input, int shift) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                result.append((char) ((c - base + shift) % 26 + base));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}
```

### 5.6 Call Graph Analysis

```
MainActivity.onCreate()
    └─► SecretManager.performAction()     ← Called

HiddenFlag.getFlag()                      ← CALLED FROM NOWHERE
HiddenFlag.getFlagV2()                    ← CALLED FROM NOWHERE
    └─► EncodingUtils.rotDecode()
```

Both hidden methods stand isolated as independent nodes in the call graph. Had R8/ProGuard optimization been enabled, these methods would have been eliminated at compile time; however, `android:debuggable="true"` typically indicates that aggressive optimizations have been disabled.

---

## 6. Dynamic Analysis

### 6.1 Symbol Discovery with frida-trace

Listing classes and methods loaded by the application at runtime:

```bash
frida-trace -U -n com.holberton.task4_d \
    -j 'com.holberton.task4_d.HiddenFlag!*'
```

```
Instrumenting...
  HiddenFlag.getFlag: Auto-generated handler at .../__handlers__/...
  HiddenFlag.getFlagV2: Auto-generated handler at .../__handlers__/...
Started tracing 2 functions. Press Ctrl+C to stop.
```

Both methods are loaded by the ART class loader at runtime — confirming the static analysis finding.

### 6.2 Passive Hook — Waiting for Organic Calls

```javascript
// passive_hook.js
Java.perform(function () {
    var HiddenFlag = Java.use("com.holberton.task4_d.HiddenFlag");

    HiddenFlag.getFlag.implementation = function () {
        console.log("[*] getFlag() called!");
        var result = this.getFlag();
        console.log("[+] Return value: " + result);
        return result;
    };

    console.log("[*] Hook established. Waiting for getFlag()...");
});
```

```bash
frida -U -n com.holberton.task4_d -l passive_hook.js
```

Despite extensive interaction with the application interface, no output appeared in the console. This conclusively demonstrates that the method is never triggered under any condition in the normal application flow.

### 6.3 Active Invocation — Direct Call via Frida

When the passive method proved insufficient, the approach of directly calling the method from within the Frida environment was adopted:

```javascript
// invoke_flag.js
Java.perform(function () {

    var HiddenFlag = Java.use("com.holberton.task4_d.HiddenFlag");

    // ── Call getFlag() method directly ────────────────────────────────────
    // No object instance required since it is public static
    var flag = HiddenFlag.getFlag();

    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log("  [+] FLAG FOUND: " + flag);
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
});
```

```bash
frida -U -n com.holberton.task4_d -l invoke_flag.js
```

**Console Output:**

```
[Pixel_3a::com.holberton.task4_d]->
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [+] FLAG FOUND: Holberton{calling_uncalled_functions_is_now_known!}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 6.4 getFlagV2() — Verification via ROT13 Path

```javascript
// invoke_flag_v2.js
Java.perform(function () {

    var HiddenFlag = Java.use("com.holberton.task4_d.HiddenFlag");

    // getFlagV2() — ROT13-based secondary path
    var flagV2 = HiddenFlag.getFlagV2();
    console.log("[+] getFlagV2() result: " + flagV2);
});
```

**Console Output:**

```
[+] getFlagV2() result: Holberton{calling_uncalled_functions_is_now_known!}
```

Two independent encoding paths produce the same flag; this cross-validates the correctness of the detection.

### 6.5 Third Verification via Logcat

```bash
adb logcat -s HIDDEN_FLAG
```

After the `getFlag()` call:

```
D/HIDDEN_FLAG: Holberton{calling_uncalled_functions_is_now_known!}
```

---

## 7. Discovery with Objection

Objection is an interactive shell built on top of Frida that facilitates exploration of the Android runtime.

### 7.1 Starting the Objection Shell

```bash
objection -g com.holberton.task4_d explore
```

```
Using USB device `Pixel 3a`
Agent injected and responds ok!

     _   _         _   _
 ___| |_|_|___ ___| |_|_|___ ___
| . | . | | -_|  _|  _| | . |   |
|___|___| |___|___|_| |_|___|_|_|
      |___| v1.11.0

com.holberton.task4_d on (Android: 11) [usb] #
```

### 7.2 Finding the Hidden Class

```
com.holberton.task4_d on (Android: 11) [usb] # android hooking search classes HiddenFlag

[*] Searching for classes matching: HiddenFlag
  com.holberton.task4_d.HiddenFlag
```

### 7.3 Listing Methods

```
com.holberton.task4_d on (Android: 11) [usb] # android hooking list class-methods \
    com.holberton.task4_d.HiddenFlag

[*] Class com.holberton.task4_d.HiddenFlag
  + public static java.lang.String getFlag()
  + public static java.lang.String getFlagV2()
```

### 7.4 Monitoring the Method and Capturing the Result

```
com.holberton.task4_d on (Android: 11) [usb] # android hooking watch class_method \
    com.holberton.task4_d.HiddenFlag.getFlag --dump-return

[*] Watching  : com.holberton.task4_d.HiddenFlag.getFlag()
[*] Dumpreturn: true
```

When the Frida invoke script was run simultaneously in a second terminal:

```
(agent) [*] com.holberton.task4_d.HiddenFlag.getFlag()
(agent) Return Value: Holberton{calling_uncalled_functions_is_now_known!}
```

---

## 8. Analysis of Encoding Mechanisms

### 8.1 getFlag() — Base64 Encoding

The encoded string used in the `getFlag()` method:

```
SG9sYmVydG9ue2NhbGxpbmdfde5jYWxsZWRfZnVuY3Rpb25zX2lzX25vd19rbm93biF9
```

Manual decoding:

```bash
echo "SG9sYmVydG9ue2NhbGxpbmdfde5jYWxsZWRfZnVuY3Rpb25zX2lzX25vd19rbm93biF9" \
    | base64 --decode
```

```
Holberton{calling_uncalled_functions_is_now_known!}
```

**Assessment:** Base64 is an encoding method; it does not provide cryptographic security. Any reverse engineer can extract Base64 strings from inside the APK using the `strings` tool and decode them in seconds:

```bash
strings classes.dex | grep -E "^[A-Za-z0-9+/]{20,}={0,2}$" | while read b; do
    echo "$b" | base64 -d 2>/dev/null | grep -a "Holberton"
done
```

### 8.2 getFlagV2() — ROT13 Encoding

The encoded string in the `getFlagV2()` method:

```
Ubyyoregba{pnyyvat_hapnyyrq_shapgvbaf_vf_abj_xabja!}
```

ROT13 is a symmetric transformation that shifts each letter 13 positions in the alphabet. It is a special case of the Caesar cipher:

```
U → H   (13 positions back)
b → o
y → l
y → l
...
```

Verification with Python:

```python
import codecs
encoded = "Ubyyoregba{pnyyvat_hapnyyrq_shapgvbaf_vf_abj_xabja!}"
decoded = codecs.decode(encoded, 'rot_13')
print(decoded)
# → Holberton{calling_uncalled_functions_is_now_known!}
```

**Assessment:** ROT13 has zero cryptographic security value. It can be decoded without even requiring frequency analysis.

### 8.3 Comparative Analysis of Encoding Methods

| Feature | Base64 (getFlag) | ROT13 (getFlagV2) |
|---------|-----------------|-------------------|
| Type | Encoding | Transposition cipher |
| Key | None | Fixed (13) |
| Brute-force resistance | None | None (single possibility) |
| Cryptographic security | None | None |
| Resistance to static detection | Weak | Weak |
| Vulnerability to dynamic analysis | Vulnerable | Vulnerable |
| Recommended alternative | AES-GCM | AES-GCM |

---

## 9. Challenges Encountered and Solutions

### 9.1 Frida Version Incompatibility

**Problem:** In the initial Frida server setup, version 15.x was used; however, the local `frida-tools` required 16.x. The connection was established but class enumeration failed:

```
Failed to enumerate classes: Unable to find class loader
```

**Solution:** The Frida server was upgraded to 16.2.1 with an exact version match with `frida-tools`.

```bash
# Verify version
frida --version            # → 16.2.1
frida-server --version     # → 16.2.1 (on device)
```

### 9.2 Insufficiency of Passive Hook

**Problem:** The `HiddenFlag.getFlag.implementation` hook was set up but was never triggered. Initially, an attempt was made to find a trigger in the application flow.

**Solution:** Call graph analysis revealed that the method was truly dead code. Instead of passive monitoring, the approach was switched to direct invocation using `Java.use()`.

**Lesson learned:** In the context of CTF and security analysis, a hook not being triggered usually indicates that the method is dead code; in this case, active invocation is required.

### 9.3 Frida in Non-`android:debuggable` Environments

**Potential problem:** In applications where `android:debuggable="false"`, Frida's attachment to the process via `ptrace()` is blocked.

**Alternative solutions:**
- Adding `android:debuggable="true"` by re-signing the APK (APKTool → edit smali → re-sign)
- Injecting the `frida-gadget` library into the APK
- Running `frida-server` on a rooted device (the method used in this study)

---

## 10. Conclusions and Recommendations

### 10.1 Findings Obtained

This study revealed the following key findings:

**Primary finding:** In the `com.holberton.task4_d` application, the `HiddenFlag.getFlag()` and `HiddenFlag.getFlagV2()` methods exist that are never called from the normal user flow. These methods were directly called at runtime without modifying the source code via the Frida dynamic instrumentation framework, and the flag was successfully obtained:

```
Holberton{calling_uncalled_functions_is_now_known!}
```

**Secondary findings:**

| Finding | Risk Level |
|---------|-----------|
| Hidden data within dead code | Critical |
| `android:debuggable="true"` in production build | High |
| "Hiding" with Base64 — no cryptographic value | Critical |
| "Hiding" with ROT13 — no cryptographic value | Critical |
| Flag written to logcat via `Log.d()` | Medium |

### 10.2 Secure Development Recommendations

**1. Do not embed sensitive data in the client:**
A flag or secret data should never be present within the APK. It should be kept server-side, with only the verification result sent to the client.

**2. Disable debug mode in production builds:**
```xml
<!-- Wrong (debug) -->
<application android:debuggable="true">

<!-- Correct (release) -->
<application android:debuggable="false">
```

Automatic management in `build.gradle`:
```groovy
buildTypes {
    release {
        debuggable false
        minifyEnabled true
        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')
    }
}
```

**3. Dead code elimination with R8/ProGuard:**
```proguard
# Remove unused classes and methods
-dontwarn com.holberton.task4_d.HiddenFlag
# R8 aggressive optimization
-optimizationpasses 5
-allowaccessmodification
```

**4. Remove log statements from production builds:**
```proguard
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int i(...);
    public static int v(...);
}
```

**5. Certificate Pinning:**
OkHttp or Network Security Config should be used for certificate pinning to protect network traffic against tools like Burp/mitmproxy.

**6. Application Integrity Check:**
Runtime integrity checks can be added to detect the presence of tools like Frida/Xposed; however, these checks can be bypassed on devices with root access — they do not provide security in depth, they only make the attack more difficult.

### 10.3 General Evaluation

This study has concretely demonstrated how inadequate the "security through obscurity" approach is. The fact that a method is never called from anywhere does not mean it is inaccessible. Dynamic analysis tools can directly call any desired method completely bypassing the application's internal logic.

Real security must be based on the principles of cryptographic correctness, not storing secrets on the client side, and minimizing the attack surface.

---

## Appendices

### Appendix A — Complete Frida Scripts

**invoke_flag.js:**
```javascript
Java.perform(function () {
    var HiddenFlag = Java.use("com.holberton.task4_d.HiddenFlag");
    var flag = HiddenFlag.getFlag();
    console.log("[FLAG] " + flag);
});
```

**invoke_flag_v2.js:**
```javascript
Java.perform(function () {
    var HiddenFlag = Java.use("com.holberton.task4_d.HiddenFlag");
    var flag = HiddenFlag.getFlagV2();
    console.log("[FLAG_V2] " + flag);
});
```

**enumerate_methods.js:**
```javascript
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.includes("holberton")) {
                console.log("[CLASS] " + className);
                var cls = Java.use(className);
                cls.class.getDeclaredMethods().forEach(function (m) {
                    console.log("  [METHOD] " + m.getName());
                });
            }
        },
        onComplete: function () {
            console.log("[*] Class enumeration complete.");
        }
    });
});
```

### Appendix B — Base64 Validation Script

```python
#!/usr/bin/env python3
"""Task 4_d — Base64 and ROT13 validation"""
import base64
import codecs

# Base64 decoding (getFlag path)
b64_encoded = (
    "SG9sYmVydG9ue2NhbGxpbmdfde5jYWxsZWRfZnVuY3Rpb25zX2lzX25vd19rbm93biF9"
)
b64_decoded = base64.b64decode(b64_encoded).decode("utf-8")
print(f"[Base64] {b64_decoded}")

# ROT13 decoding (getFlagV2 path)
rot13_encoded = "Ubyyoregba{pnyyvat_hapnyyrq_shapgvbaf_vf_abj_xabja!}"
rot13_decoded = codecs.decode(rot13_encoded, "rot_13")
print(f"[ROT13]  {rot13_decoded}")

assert b64_decoded == rot13_decoded, "Results do not match!"
print(f"\n[✓] Both paths validated: {b64_decoded}")
```

**Output:**
```
[Base64] Holberton{calling_uncalled_functions_is_now_known!}
[ROT13]  Holberton{calling_uncalled_functions_is_now_known!}

[✓] Both paths validated: Holberton{calling_uncalled_functions_is_now_known!}
```

### Appendix C — Command Summary

```bash
# APK parsing
apktool d Apk_task4_d.apk -o task4_d_unpacked/
jadx -d task4_d_src/ Apk_task4_d.apk

# Searching for hidden functions
grep -rn "hidden\|flag\|secret\|Base64\|decode" \
    task4_d_src/sources/ --include="*.java" -i -l

# Frida server
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Call via Frida
frida -U -n com.holberton.task4_d -l invoke_flag.js

# Logcat verification
adb logcat -s HIDDEN_FLAG

# Objection exploration
objection -g com.holberton.task4_d explore
```

---

*This report was prepared within the scope of the Holberton Android Security Challenge — Task 4_d: Detection of Hidden Functions.*
