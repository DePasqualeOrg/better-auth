# Better Auth Swift Client

A Swift client for [Better Auth](https://github.com/nextauthjs/better-auth) that allows iOS and macOS applications to authenticate with Better Auth servers.

## Features

- Email/password authentication
- Social authentication (OAuth)
- Session management
- JWT token management with claim access and validation
- Convenient API wrapper for authenticated requests
- Keychain integration for secure token storage
- Built as Swift Actor for thread safety
- Modern async/await API
- Automatic token refresh
- SwiftUI integration

## Requirements

- iOS 16.0+ / macOS 13.0+
- Swift 5.7+

## Installation

### Swift Package Manager

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/your-repo/better-auth-swift.git", from: "0.1.0")
]
```

Or add it directly through Xcode:
1. Go to File > Swift Packages > Add Package Dependency
2. Enter the repository URL: `https://github.com/your-repo/better-auth-swift.git`
3. Choose the version you want to install

## Usage

### Initialization

```swift
import BetterAuth

// Initialize the client
let authClient = BetterAuth(config: BetterAuthConfig(
    baseURL: "https://your-api.com",
    basePath: "/api/auth" // Optional, defaults to "/api/auth"
))
```

### Authentication

#### Sign In with Email/Password

```swift
Task {
    do {
        let session = try await authClient.signInWithEmail(email: "user@example.com", password: "password")
        print("Signed in as: \(session.user.name ?? "User")")
    } catch {
        print("Sign in failed: \(error.localizedDescription)")
    }
}
```

#### Sign In with Magic Link

```swift
Task {
    do {
        let success = try await authClient.signInWithMagicLink(
            email: "user@example.com",
            name: "John Doe" // Optional, used for new users
        )
        if success {
            print("Magic link sent! Please check your email")
        }
    } catch {
        print("Failed to send magic link: \(error.localizedDescription)")
    }
}
```

#### Verify Magic Link

When a user clicks on a magic link, you need to handle the token verification:

```swift
// The token is extracted from the URL
let token = "received-token-from-url"

Task {
    do {
        let session = try await authClient.verifyMagicLink(token: token)
        print("Magic link verified, signed in as: \(session.user.name ?? "User")")
    } catch {
        print("Magic link verification failed: \(error.localizedDescription)")
    }
}
```

The client includes a dedicated `MagicLinkVerificationView` for handling this process in SwiftUI apps, and the URL handler will automatically process magic link tokens.

#### Sign In with Social Provider

```swift
Task {
    do {
        let url = try await authClient.signInWithSocial(provider: "github")
        // Open this URL in a web view or Safari
        await UIApplication.shared.open(url)
    } catch {
        print("Failed to start social auth: \(error.localizedDescription)")
    }
}
```

#### Handle Auth Callback

Add this to your SceneDelegate or main SwiftUI App:

```swift
// For UIKit apps in SceneDelegate:
func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
    guard let url = URLContexts.first?.url else { return }
    if url.scheme == "better-auth" {
        _ = authClient.handleAuthCallback(url: url)
    }
}

// For SwiftUI apps, use the provided modifier:
@main
struct MyApp: App {
    let authClient = BetterAuth(config: BetterAuthConfig(baseURL: "https://your-api.com"))
    
    var body: some Scene {
        WindowGroup {
            ContentView(authClient: authClient)
                .handleBetterAuthURL(authClient: authClient, scheme: "better-auth")
        }
    }
}
```

#### Sign Up with Email/Password

```swift
Task {
    do {
        let session = try await authClient.signUpWithEmail(
            email: "user@example.com", 
            password: "password", 
            name: "John Doe"
        )
        print("Signed up as: \(session.user.name ?? "User")")
    } catch {
        print("Sign up failed: \(error.localizedDescription)")
    }
}
```

#### Sign Out

```swift
Task {
    do {
        try await authClient.signOut()
        print("Signed out successfully")
    } catch {
        print("Sign out failed: \(error.localizedDescription)")
    }
}
```

### Session Management

#### Get Current Session

```swift
Task {
    do {
        let session = try await authClient.getSession()
        print("User: \(session.user.name ?? "Unknown")")
    } catch {
        print("Failed to get session: \(error.localizedDescription)")
    }
}
```

#### Observe Session Changes

```swift
Task {
    // Add an observer
    let observerId = await authClient.addSessionObserver { session in
        if let session = session {
            print("Session active: \(session.user.name ?? "User")")
        } else {
            print("No active session")
        }
    }
    
    // Later, remove the observer when no longer needed
    await authClient.removeSessionObserver(id: observerId)
}
```

### JWT Token Management

```swift
Task {
    do {
        let token = try await authClient.getJWTToken()
        // Use the token manually for API requests
        var request = URLRequest(url: URL(string: "https://api.example.com/data")!)
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        // ... make request
    } catch {
        print("Failed to get JWT token: \(error.localizedDescription)")
    }
}
```

#### Using the API Wrapper

The client provides a clean API for making authenticated requests:

```swift
Task {
    do {
        // Create API URL using the helper method
        let apiBaseURL = "https://api.example.com"
        
        // GET request
        let userProfileURL = try BetterAuth.url(baseURL: apiBaseURL, path: "/user/profile")
        let userData: UserData = try await authClient.request(
            method: BetterAuth.HTTPMethod.get,
            url: userProfileURL
        )
        
        // POST with body
        let updateURL = try BetterAuth.url(baseURL: apiBaseURL, path: "/user/update")
        let body: [String: Any] = [
            "name": "Updated Name",
            "email": "updated@example.com"
        ]
        let updatedUser: UserData = try await authClient.request(
            method: BetterAuth.HTTPMethod.post,
            url: updateURL, 
            body: body
        )
        
        // Using custom headers
        let customURL = try BetterAuth.url(baseURL: apiBaseURL, path: "/custom-endpoint")
        let headers = ["X-Custom-Header": "Value"]
        let customData: SomeData = try await authClient.request(
            method: BetterAuth.HTTPMethod.get,
            url: customURL, 
            headers: headers
        )
        
        // Using a custom HTTP method
        let specialURL = try BetterAuth.url(baseURL: apiBaseURL, path: "/special-update")
        let specialData: SpecialData = try await authClient.request(
            method: BetterAuth.HTTPMethod.patch,
            url: specialURL,
            body: ["value": 123],
            headers: ["X-Special": "true"],
            retry: true  // Auto-retry on 401 (default)
        )
        
        print("User name: \(userData.name)")
    } catch BetterAuthError.apiError(let message, _) {
        print("API error: \(message)")
    } catch {
        print("Request failed: \(error.localizedDescription)")
    }
}
```

#### Checking JWT Token Claims

```swift
if let claims = authClient.getJWTClaims() {
    if let userId = claims["sub"] as? String {
        print("User ID from token: \(userId)")
    }
    
    if let expiration = claims["exp"] as? TimeInterval {
        let expirationDate = Date(timeIntervalSince1970: expiration)
        print("Token expires at: \(expirationDate)")
    }
}
```

### Using SwiftUI

The package includes ready-to-use SwiftUI views to integrate authentication into your app:

```swift
import SwiftUI
import BetterAuth

struct ContentView: View {
    let authClient: BetterAuth
    
    var body: some View {
        // Pre-built authentication flow with sign in, sign up, and profile views
        AuthView(authClient: authClient)
    }
}
```

For more control, you can use the individual components:

```swift
struct CustomAuthView: View {
    @State private var isSignedIn = false
    let authClient: BetterAuth
    
    var body: some View {
        if isSignedIn {
            ProfileView(authClient: authClient) {
                isSignedIn = false
            }
        } else {
            SignInView(authClient: authClient) { _ in
                isSignedIn = true
            }
        }
    }
}
```

## Thread Safety

The `BetterAuth` client is implemented as a Swift Actor, ensuring thread safety when accessing shared state. This means you can safely call its methods from different threads without worrying about race conditions.

## Configuration

The Swift client is configured to work with Better Auth servers that have the "bearer" and "jwt" plugins enabled. It:

1. Uses bearer tokens as refresh tokens, stored securely in the keychain
2. Stores JWT tokens in memory for API requests
3. Automatically refreshes JWT tokens when they expire

## License

MIT