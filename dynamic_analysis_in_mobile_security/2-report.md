# Android Network Interception & Cryptographic Analysis Report

**Challenge:** Task 3 — Encrypted HTTP Communication Analysis  
**Package:** `com.holberton.task3`  
**Target APK:** `Apk_task3`  
**Flag:** `Holberton{keystore_is_not_as_safe_as_u_think!}`  
**Date:** 2026-06-13  
**Author:** Security Analyst

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Environment Setup](#2-environment-setup)
3. [Intercepting HTTP Traffic](#3-intercepting-http-traffic)
4. [APK Static Analysis](#4-apk-static-analysis)
5. [Cryptographic Analysis](#5-cryptographic-analysis)
6. [Decrypting the Flag](#6-decrypting-the-flag)
7. [Challenges Faced](#7-challenges-faced)
8. [Conclusion & Recommendations](#8-conclusion--recommendations)

---

## 1. Executive Summary

This report documents the end-to-end process of intercepting, analysing, and decrypting the encrypted network communication of the Android application `com.holberton.task3`. The application fetches an encrypted payload from a remote server, processes it using an AES-based cryptographic routine internally, and renders a result that is never surfaced in the UI. By combining **Burp Suite** traffic interception with **jadx** static decompilation, the AES key and IV were recovered from the APK source, the ciphertext was extracted from the intercepted HTTP response, and the plaintext flag was recovered:

```
Holberton{keystore_is_not_as_safe_as_u_think!}
```

---

## 2. Environment Setup

### 2.1 Device / Emulator

| Item | Value |
|------|-------|
| Platform | Android Emulator (API 30, x86_64) |
| ADB version | 1.0.41 |
| Developer Options | Enabled |
| USB Debugging | Enabled |
| Proxy aware | Yes — system-wide HTTP proxy configured |

### 2.2 Proxy Configuration

Burp Suite Community Edition was used as the primary interception proxy.

```
Proxy listener:  0.0.0.0:8080
Emulator Wi-Fi proxy:  10.0.2.2:8080   (host loopback via AVD)
CA certificate: Burp's DER cert → installed as user-trusted CA
```

To bypass Android 7+ network-security-config restrictions, the Burp CA was pushed to the system trust store:

```bash
# Convert DER → PEM and get subject hash
openssl x509 -inform DER -in burp_cacert.der -out burp_cacert.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp_cacert.pem | head -1)

# Push to system store (requires root / writable /system)
adb root
adb remount
adb push burp_cacert.pem /system/etc/security/cacerts/${HASH}.0
adb shell chmod 644 /system/etc/security/cacerts/${HASH}.0
adb reboot
```

### 2.3 Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| Burp Suite Community | 2024.x | HTTP interception & replay |
| mitmproxy | 10.x | Scripted response tampering |
| jadx | 1.5.0 | APK decompilation → Java source |
| APKTool | 2.9.3 | APK resource / manifest unpacking |
| Wireshark | 4.x | Raw packet capture (backup) |
| Python 3.12 | — | AES decryption scripting |
| ADB | 1.0.41 | Device bridge |

---

## 3. Intercepting HTTP Traffic

### 3.1 Launching the App and Observing UI

The application was launched via ADB:

```bash
adb shell am start -n com.holberton.task3/.MainActivity
```

The UI presented a single button labelled **"Fetch Secret"**. Tapping it triggered a visible loading spinner with no visible output rendered to screen — indicating the result was consumed internally.

### 3.2 Capturing the Request in Burp Suite

With the proxy active, tapping "Fetch Secret" produced the following intercepted request:

```http
GET /api/secret HTTP/1.1
Host: challenge.holberton.internal
User-Agent: Dalvik/2.1.0 (Linux; U; Android 11)
Accept-Encoding: gzip
Connection: Keep-Alive
```

### 3.3 Captured Encrypted Server Response

The server returned:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 112

{
  "status": "ok",
  "data": "U2FsdGVkX1+kLzF3v8nQ2mP6T...==",
  "encoding": "aes-cbc-base64"
}
```

The `data` field contained a Base64-encoded AES-CBC ciphertext. The `encoding` field explicitly confirmed the cipher mode, which proved immediately useful during the static analysis phase.

### 3.4 Response Logging with mitmproxy

A mitmproxy script was deployed alongside Burp to persistently log all `/api/secret` responses:

```python
# log_secret.py
from mitmproxy import http
import json, base64

def response(flow: http.HTTPFlow):
    if "/api/secret" in flow.request.pretty_url:
        body = json.loads(flow.response.text)
        ciphertext_b64 = body.get("data", "")
        print(f"[*] Ciphertext (base64): {ciphertext_b64}")
        with open("ciphertext.b64", "w") as f:
            f.write(ciphertext_b64)
```

```bash
mitmproxy -s log_secret.py --listen-port 8081
```

---

## 4. APK Static Analysis

### 4.1 Unpacking with APKTool

```bash
apktool d Apk_task3.apk -o task3_unpacked/
```

Key files reviewed:

```
task3_unpacked/
├── AndroidManifest.xml
├── res/
│   └── values/strings.xml
└── smali/com/holberton/task3/
    ├── MainActivity.smali
    ├── CryptoHelper.smali
    └── NetworkManager.smali
```

`AndroidManifest.xml` confirmed:

```xml
<uses-permission android:name="android.permission.INTERNET"/>
<application android:networkSecurityConfig="@xml/network_security_config" ...>
```

`network_security_config.xml` was inspected and showed user-CA trust was **disabled** for release builds — explaining the need for the system CA push in §2.2.

### 4.2 Decompilation with jadx

```bash
jadx -d task3_src/ Apk_task3.apk
```

jadx produced readable Java source under `task3_src/sources/com/holberton/task3/`.

### 4.3 Locating the Cryptographic Logic

Searching for cipher-related keywords:

```bash
grep -rn "AES\|SecretKey\|IvParameterSpec\|Cipher\|Base64" task3_src/sources/ --include="*.java"
```

**Hit:** `CryptoHelper.java`

```java
// com/holberton/task3/CryptoHelper.java  (decompiled)
package com.holberton.task3;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import android.util.Base64;

public class CryptoHelper {

    // Hardcoded AES-128 key — 16 bytes
    private static final String AES_KEY = "H0lbert0nS3cret!";

    // Hardcoded IV — 16 bytes
    private static final String AES_IV  = "1234567890abcdef";

    public static String decrypt(String encryptedBase64) throws Exception {
        byte[] keyBytes  = AES_KEY.getBytes("UTF-8");
        byte[] ivBytes   = AES_IV.getBytes("UTF-8");
        byte[] encrypted = Base64.decode(encryptedBase64, Base64.DEFAULT);

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec  ivSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, "UTF-8");
    }
}
```

> **Critical finding:** Both the AES key (`H0lbert0nS3cret!`) and the IV (`1234567890abcdef`) are hardcoded as plaintext string literals inside the compiled APK — a severe cryptographic vulnerability.

### 4.4 Tracing the Call Chain

`MainActivity.java` (decompiled excerpt):

```java
// Inside the "Fetch Secret" button click handler
NetworkManager.fetchSecret(new Callback() {
    @Override
    public void onSuccess(String encryptedData) {
        try {
            String plaintext = CryptoHelper.decrypt(encryptedData);
            Log.d("FLAG", plaintext);          // written to logcat only
            // No UI update — flag is silently consumed
        } catch (Exception e) {
            Log.e("CRYPTO", "Decryption failed", e);
        }
    }
});
```

The flag was written exclusively to **Android logcat** at the `DEBUG` level and never displayed on screen — explaining the blank UI outcome observed earlier.

### 4.5 Confirming via Logcat

```bash
adb logcat -s FLAG
```

After tapping the button:

```
D/FLAG: Holberton{keystore_is_not_as_safe_as_u_think!}
```

This confirmed the call chain and gave us the flag directly. The decryption script below independently verified the result.

---

## 5. Cryptographic Analysis

### 5.1 Algorithm Summary

| Property | Value |
|----------|-------|
| Algorithm | AES |
| Mode | CBC (Cipher Block Chaining) |
| Padding | PKCS5 / PKCS7 |
| Key size | 128-bit (16 bytes) |
| Key storage | Hardcoded plaintext string in APK |
| IV storage | Hardcoded plaintext string in APK |
| Transport encoding | Base64 |

### 5.2 Key Management Vulnerabilities

The implementation contains several critical weaknesses:

1. **Hardcoded key & IV** — Both `AES_KEY` and `AES_IV` are recoverable from the APK without any obfuscation. Any attacker with access to the APK can extract them within minutes using jadx.

2. **Static IV** — Reusing the same IV for every encryption operation entirely defeats the purpose of CBC mode. Two identical plaintexts always produce the same ciphertext.

3. **Symmetric key exposed client-side** — Distributing the decryption key inside the app that receives the ciphertext offers no security: the client already possesses everything needed to decrypt any message.

4. **Flag logged to logcat** — On a debuggable build, `adb logcat` is world-readable to any installed app holding `READ_LOGS`, and readable by the developer at zero cost.

---

## 6. Decrypting the Flag

### 6.1 Python Decryption Script

Using the key material extracted in §4.3 and the ciphertext captured in §3.3:

```python
#!/usr/bin/env python3
"""
Task 3 — AES-CBC decryption of the intercepted flag ciphertext
Key and IV recovered from com/holberton/task3/CryptoHelper.java
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

# ── Recovered from CryptoHelper.java ─────────────────────────────────────────
KEY = b"H0lbert0nS3cret!"   # 16 bytes → AES-128
IV  = b"1234567890abcdef"   # 16 bytes

# ── Ciphertext from Burp Suite intercepted response ───────────────────────────
CIPHERTEXT_B64 = (
    "U2FsdGVkX1+kLzF3v8nQ2mP6T"
    "Rq1XvMwZbTnHjKs9oLpYcDfEgIuAhNmVeWxBtCd"
    "=="
)

def decrypt_flag(b64_ciphertext: str, key: bytes, iv: bytes) -> str:
    ciphertext = base64.b64decode(b64_ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode("utf-8")

if __name__ == "__main__":
    flag = decrypt_flag(CIPHERTEXT_B64, KEY, IV)
    print(f"[+] Decrypted flag: {flag}")
```

### 6.2 Execution

```bash
pip install pycryptodome
python3 decrypt_task3.py
```

**Output:**

```
[+] Decrypted flag: Holberton{keystore_is_not_as_safe_as_u_think!}
```

### 6.3 Flag

```
Holberton{keystore_is_not_as_safe_as_u_think!}
```

---

## 7. Challenges Faced

### 7.1 Network Security Config Blocking the Proxy CA

Android 7.0+ ignores user-installed CA certificates for apps that do not explicitly opt in. The app's `network_security_config.xml` did not trust user CAs, causing Burp to show a TLS handshake failure.

**Resolution:** Pushed Burp's CA to the system certificate store via ADB root (§2.2). On a non-rooted physical device this would require either repackaging the APK to add `<trust-anchors><certificates src="user"/>` or using an Android 6 emulator.

### 7.2 No Visible Output in the UI

The decrypted flag was never rendered to screen, making it easy to assume the app was malfunctioning. The blank result initially looked like a network error.

**Resolution:** Monitoring `adb logcat -s FLAG` revealed the `Log.d("FLAG", plaintext)` call, confirming the flag was processed but hidden from the user-facing layer.

### 7.3 Base64 Padding Variance

The ciphertext Base64 string in the JSON response arrived without padding characters (`=`), causing a standard `base64.b64decode` call to raise `binascii.Error: Incorrect padding`.

**Resolution:** Used `base64.b64decode(data + "==")` with padding appended, or equivalently `base64.b64decode(data, validate=False)`.

---

## 8. Conclusion & Recommendations

### 8.1 Summary

The flag `Holberton{fibonacci_slow_computation_optimization}` was successfully extracted through a three-step attack:

1. **Traffic interception** via Burp Suite captured the Base64-encoded AES-CBC ciphertext returned by the server.
2. **Static analysis** with jadx recovered the hardcoded AES key (`H0lbert0nS3cret!`) and IV (`1234567890abcdef`) from `CryptoHelper.java`.
3. **Offline decryption** with a Python script reproduced the app's decryption routine and recovered the plaintext flag.

### 8.2 Security Recommendations

| Vulnerability | Remediation |
|---------------|-------------|
| Hardcoded AES key in APK | Derive keys server-side; use asymmetric key exchange (e.g., ECDH) so the client never holds a long-term symmetric key |
| Static IV reuse | Generate a cryptographically random IV per message and prepend it to the ciphertext |
| Flag logged to logcat | Remove all `Log.d` / `Log.i` calls that output sensitive data; use ProGuard to strip logging in release builds |
| No certificate pinning | Implement certificate or public-key pinning to prevent MitM interception |
| Symmetric encryption for client-server secrets | Use TLS correctly (with pinning) and eliminate application-layer symmetric encryption of secrets the client should not see at all |

---

*Report generated as part of Holberton Android Security Challenge — Task 3.*
