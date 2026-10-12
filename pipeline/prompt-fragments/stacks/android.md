---
id: android
version: 1
covers: []
standards: ["masvs2", "cwe"]
max_tokens: 1500
---
## Runtime and framework model
An Android application in Kotlin or Java (Jetpack, Compose, or Views), sometimes with native
libraries via the NDK, Flutter, or React Native. Apps run in per-UID sandboxes; inter-app
communication goes through Binder-backed intents, content providers, and bound services. The
manifest declares components, permissions, and platform behaviour switches.

## Trust and interface layer
- Entry points: exported activities, services, broadcast receivers, content providers, deep
  links (`<data android:scheme>`), App Links, push messages, WebView JavaScript interfaces, and
  files or clipboard data from other apps.
- Other apps on the device are untrusted; any app can send an intent to an exported component.
- The backend is a separate trust domain: client checks protect nothing server-side.
- Rooted devices and instrumentation (Frida) mean client-side checks, obfuscation, and root
  detection delay an attacker but never enforce policy.

## Idiomatic security mechanisms
- `android:exported="false"` (mandatory explicit value since API 31), `android:permission` with
  `protectionLevel="signature"`, `checkCallingPermission`.
- Explicit intents, `PendingIntent.FLAG_IMMUTABLE`, `setPackage` on implicit intents.
- Network Security Config with no cleartext and optional pins; `HttpsURLConnection`/OkHttp
  default verification.
- Android Keystore keys with `setUserAuthenticationRequired`, `BiometricPrompt` with a
  `CryptoObject`; EncryptedSharedPreferences or Jetpack Security alternatives.
- `FileProvider` with narrow paths instead of `file://` URIs.

## Stack-specific pitfalls
- Intent redirection: `startActivity(getIntent().getParcelableExtra("next"))`.
- `WebView` with `addJavascriptInterface`, `setAllowUniversalAccessFromFileURLs(true)`,
  `shouldOverrideUrlLoading` trusting any URL, `loadUrl` from extras.
- Content providers with `openFile` path traversal, SQL built from `selection` arguments.
- Tokens in `SharedPreferences`, logs (`Log.d`), or external storage; `allowBackup` true.
- Custom `X509TrustManager` or `HostnameVerifier` accepting all.
- Dynamic code loading (`DexClassLoader`) from writable storage.
- Secrets embedded in the APK (`strings.xml`, `BuildConfig`, native libraries).
- `FLAG_SECURE` missing on sensitive screens; tapjacking on permission-granting UI.
- Native libraries (`System.loadLibrary`) parsing app or network data without bounds checks;
  JNI functions trusting `jsize` values from Java callers.

## Build and deployment facts to check
- Merged manifest (libraries can add exported components), `targetSdkVersion` and
  `minSdkVersion`.
- Build variants and flavours: `debuggable`, `usesCleartextTraffic`, network security config per
  variant.
- R8/ProGuard settings and native libraries packaged per ABI.
- Gradle dependency versions and SDKs (analytics, ads) that add components or data collection.
- Signing configuration and whether release builds use the debug key.
