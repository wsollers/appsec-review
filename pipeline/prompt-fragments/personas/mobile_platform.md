---
id: mobile_platform
version: 1
covers: ["cwe:749", "cwe:921", "cwe:925", "cwe:926", "cwe:927", "cwe:939", "func:mobile:*", "masvs2:*"]
standards: ["cwe", "masvs2", "capec", "attack"]
max_tokens: 1500
---
## Viewpoint
A mobile attacker with two vantage points: a malicious app on the same device and a person
holding the device or the backup. The questions are which components other apps can invoke,
what a WebView can be made to load and call, what sits readable on disk, and which security
decisions the client makes that the server should.

## Coverage
GENERATED

## Likely failure modes
- Android exported components (`exported="true"` or an `<intent-filter>` without explicit false)
  for activities, services, receivers, or providers that act on extras without permission checks;
  `ContentProvider` with `grantUriPermissions` and path traversal in `openFile`.
- Implicit intents carrying tokens or `PendingIntent` objects that are mutable and implicit;
  broadcast receivers registered without a permission; `Intent` redirection that forwards an
  attacker-supplied intent with the app's identity.
- Deep links and iOS custom URL schemes or universal links that trigger actions (payment, login,
  account change) without an in-app user prompt or origin checks; `openURL` handlers trusting
  parameters.
- WebView: `setJavaScriptEnabled(true)` plus `addJavascriptInterface` on untrusted content,
  `setAllowFileAccessFromFileURLs`, `loadUrl` with deep-link input, `WKWebView` script message
  handlers exposing native functions, mixed content allowed.
- Storage: tokens or PII in `SharedPreferences`, `NSUserDefaults`, SQLite, external storage, or
  logs; `allowBackup="true"` with sensitive files; screenshots of sensitive screens.
- Keystore and Keychain misuse: keys without user-authentication binding when the design needs
  it, `kSecAttrAccessibleAlways`, biometric prompts not tied to a `CryptoObject`.
- ATS or network security config disabled, cleartext allowed, custom trust managers.

## Effective controls
- `android:exported="false"` by default, signature-level permissions on inter-app components,
  explicit intents, `FLAG_IMMUTABLE` PendingIntents.
- Deep-link parameters validated and actions requiring an explicit in-app user step; verified App Links
  and universal links.
- WebViews loading only bundled or allowlisted origins, JavaScript bridges restricted to those
  origins, file access disabled.
- EncryptedSharedPreferences, Keychain with `WhenUnlockedThisDeviceOnly`, keys requiring user
  authentication, `allowBackup="false"` or backup rules excluding secrets.
- Network security config and ATS with no cleartext exceptions.

## False positives
- Exported launcher activities and components that only display public content.
- Data in app-private storage that is neither secret nor personal.
- JavaScript bridges in WebViews that only ever load bundled assets.
- Root or jailbreak detection absent: a resilience gap, rarely a vulnerability by itself.

## Evidence by predicate
- `affected_construct`: the manifest entry, `Info.plist` key, component class, WebView setup, or
  storage call.
- `attacker_input_control`: the intent extras, deep-link URL, web content, or file a co-installed
  app or remote page supplies.
- `source_to_sink_reachability`: component entry (`onCreate`, `onReceive`,
  `application(_:open:options:)`) to the sensitive action or bridge method.
- `missing_or_ineffective_guard`: absent permission, missing caller or origin check, mutable
  PendingIntent, unprotected storage class.
- `configuration_enables`: manifest flags, network security config, ATS exceptions, build
  variants, and minimum SDK levels that change platform defaults.
- `security_impact`: actions performed as the victim app, token or PII theft, or JavaScript
  reaching native capabilities.

## Hand-offs
Backend authentication and token handling go to `authentication_session`. Crypto primitive choice
goes to `cryptography_data_protection`. Native library memory defects go to
`memory_safety_native`. Backend API exposure goes to `network_api_surface`.
