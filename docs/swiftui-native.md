# Better Auth + Native SwiftUI

This guide covers the minimal changes required to reuse your existing Better Auth backend for both a web client (cookies) and a SwiftUI app (bearer tokens).

## 1. Server Prerequisites
- Add the Bearer plugin when you initialize Better Auth so it mirrors refreshed session cookies into a `set-auth-token` response header and accepts `Authorization: Bearer ...` tokens on incoming requests.
- Keep your normal cookie/session config for the web app; browsers will continue to send cookies automatically.
- Register every mobile deep-link/redirect scheme (e.g., `myapp://auth-callback`) inside `trustedOrigins` so OAuth or passwordless links can return to the native app.

## 2. SwiftUI Networking Flow
1. **Capture the token:** After sign-in/sign-up/refresh endpoints return, read `set-auth-token` from the `HTTPURLResponse`. If it exists, persist it in the iOS Keychain (or an equivalent encrypted store).
2. **Attach automatically:** Wrap `URLSession` (custom `URLProtocol`, `URLSessionConfiguration`, or a dedicated API client) so every request adds `Authorization: Bearer <token>` when a token is available.
3. **Handle logout/expiry:** On HTTP 401/403 or when the user explicitly signs out, delete the stored token to keep the device state aligned with the Better Auth session lifecycle.

### Sample Token Handling Snippet
```swift
if let token = httpResponse.value(forHTTPHeaderField: "set-auth-token") {
    try keychain.set(token, key: "betterAuthToken")
}

var request = URLRequest(url: url)
if let token = keychain.get("betterAuthToken") {
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
}
```

## 3. Social / Deep-Link Flows
- Use `ASWebAuthenticationSession` (or similar) to open the provider’s page. Set callback URLs like `/dashboard`; Better Auth will convert them to `myapp://dashboard` when it sees a native origin.
- Ensure the app declares the matching URL scheme/Universal Link so iOS routes the callback back into SwiftUI.

## 4. Security Checklist
- Never store the token in UserDefaults or plaintext files—use Keychain/biometric-protected storage.
- Enforce HTTPS everywhere and consider SSL pinning if you own the backend.
- Keep the Better Auth instance’s rate limits, audit hooks, and additional plugins (2FA, passkeys, etc.) identical for both clients—the Bearer transport is transparent to the rest of the stack.

With these steps, the same Better Auth deployment can authenticate browsers via cookies and SwiftUI clients via bearer headers without duplicating session logic.
