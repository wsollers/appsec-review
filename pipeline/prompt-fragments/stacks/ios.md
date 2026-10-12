---
id: ios
version: 1
covers: []
standards: ["masvs2", "cwe"]
max_tokens: 1500
---
## Runtime and framework model
An iOS, iPadOS, or macOS application in Swift or Objective-C (UIKit, SwiftUI, AppKit), sometimes
with C/C++ libraries, Flutter, or React Native. Apps are sandboxed with entitlements;
inter-app communication uses URL schemes, universal links, app extensions, pasteboard, shared
app-group containers, and XPC on macOS. Objective-C runtime dynamism allows selector-based calls.

## Trust and interface layer
- Entry points: `application(_:open:options:)` and `scene(_:openURLContexts:)` for URL schemes,
  `NSUserActivity` for universal links, push notification payloads, app extension inputs,
  `WKScriptMessageHandler` callbacks, shared containers, and pasteboard reads.
- Any app can register the same custom URL scheme; scheme callbacks are not authenticated.
- macOS XPC services and helper tools must verify the connecting client's code signature.
- Jailbroken devices allow hooking of any Swift or Objective-C method, so client-side gates
  delay rather than prevent an attacker.

## Idiomatic security mechanisms
- Keychain items with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and access control flags
  (`.biometryCurrentSet`, `.userPresence`); Secure Enclave keys for signing.
- `LAContext` combined with Keychain access control rather than a boolean result.
- App Transport Security defaults (no `NSAllowsArbitraryLoads`); `URLSession` default trust
  evaluation; pinning via `NSPinnedDomains` or delegate checks that add, not replace, validation.
- Data Protection classes (`NSFileProtectionComplete`) on sensitive files.
- `WKWebView` with restricted `WKContentWorld`, origin checks on script messages.
- XPC `setCodeSigningRequirement` (macOS 13+) or audit-token checks.

## Stack-specific pitfalls
- URL handlers that perform actions (login with token, transfer, settings change) from query
  parameters without user interaction.
- `evaluatePolicy` success used as the only gate for unlocking secrets (bypassable by hooking).
- Tokens in `UserDefaults`, plist files, Core Data without protection class, or logs (`NSLog`,
  `print` in release).
- `URLSession` delegate `didReceive challenge` returning `.useCredential` for any server trust.
- `UIWebView` (deprecated) or `WKWebView` loading remote content with native bridges.
- `NSKeyedUnarchiver` without `requiresSecureCoding`; `NSCoding` on untrusted data.
- Hard-coded API secrets in the binary or `Info.plist`.
- Pasteboard leakage of secrets; missing snapshot protection on backgrounding.

## Build and deployment facts to check
- `Info.plist`: URL schemes, `NSAppTransportSecurity` exceptions, associated domains.
- Entitlements: app groups, keychain sharing, network extensions, hardened runtime on macOS.
- Build configurations (Debug vs Release) and compile-time flags that enable debug menus.
- Third-party SDK versions via Swift Package Manager, CocoaPods, or Carthage lockfiles.
- Minimum OS version, which determines available protections.
