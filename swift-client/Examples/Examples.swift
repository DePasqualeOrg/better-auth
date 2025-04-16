import SwiftUI

/**
 * Example SwiftUI view for sign in
 */
public struct SignInView: View {
  @State private var email: String = ""
  @State private var password: String = ""
  @State private var isLoading: Bool = false
  @State private var errorMessage: String? = nil

  let authClient: BetterAuth
  let onSignIn: (SessionData) -> Void

  public init(authClient: BetterAuth, onSignIn: @escaping (SessionData) -> Void) {
    self.authClient = authClient
    self.onSignIn = onSignIn
  }

  public var body: some View {
    VStack(spacing: 16) {
      Text("Sign In")
        .font(.largeTitle)
        .fontWeight(.bold)

      TextField("Email", text: $email)
        .autocorrectionDisabled(true)
      //                .textInputAutocapitalization(.never)
      //                .keyboardType(.emailAddress)
        .padding()
      //                .background(Color(.systemGray6))
        .cornerRadius(8)

      SecureField("Password", text: $password)
        .padding()
      //                .background(Color(.systemGray6))
        .cornerRadius(8)

      if let errorMessage = errorMessage {
        Text(errorMessage)
          .foregroundColor(.red)
          .font(.caption)
      }

      Button(action: {
        Task {
          await signIn()
        }
      }) {
        if isLoading {
          ProgressView()
            .progressViewStyle(CircularProgressViewStyle())
        } else {
          Text("Sign In")
            .fontWeight(.semibold)
            .foregroundColor(.white)
            .frame(maxWidth: .infinity)
        }
      }
      .padding()
      .background(Color.blue)
      .cornerRadius(8)
      .disabled(isLoading || email.isEmpty || password.isEmpty)

      Button(action: {
        Task {
          await signInWithMagicLink()
        }
      }) {
        HStack {
          Image(systemName: "envelope.fill")
          Text("Sign in with Magic Link")
        }
        .fontWeight(.semibold)
        .foregroundColor(.white)
        .frame(maxWidth: .infinity)
      }
      .padding()
      .background(Color.purple)
      .cornerRadius(8)
      .disabled(isLoading || email.isEmpty)

      Button(action: {
        Task {
          await signInWithGitHub()
        }
      }) {
        HStack {
          Image(systemName: "person.fill")
          Text("Continue with GitHub")
        }
        .fontWeight(.semibold)
        .foregroundColor(.white)
        .frame(maxWidth: .infinity)
      }
      .padding()
      .background(Color.black)
      .cornerRadius(8)
      .disabled(isLoading)
    }
    .padding()
  }

  private func signIn() async {
    guard !isLoading else { return }

    isLoading = true
    errorMessage = nil

    do {
      let session = try await authClient.signInWithEmail(email: email, password: password)
      onSignIn(session)
    } catch {
      errorMessage = error.localizedDescription
    }

    isLoading = false
  }

  private func signInWithMagicLink() async {
    guard !isLoading, !email.isEmpty else { return }

    isLoading = true
    errorMessage = nil

    do {
      let success = try await authClient.signInWithMagicLink(email: email)
      if success {
        errorMessage = nil
        // Show success message
        Task { @MainActor in
          errorMessage = "Magic link sent! Please check your email."
        }
      } else {
        errorMessage = "Failed to send magic link"
      }
    } catch {
      errorMessage = error.localizedDescription
    }

    isLoading = false
  }

  private func signInWithGitHub() async {
    guard !isLoading else { return }

    isLoading = true
    errorMessage = nil

    do {
      // Specify destination path where user should be directed after authentication
      // Similar to web client: signIn.social({ provider: "github", callbackURL: "/dashboard" })
      let url = try await authClient.signInWithSocial(
        provider: "github",
        destination: "dashboard" // No leading slash needed - will be handled by the method
      )
      // Open URL in Safari or WebView
#if os(iOS)
      await UIApplication.shared.open(url)
#elseif os(macOS)
      NSWorkspace.shared.open(url)
#endif
    } catch {
      errorMessage = error.localizedDescription
    }

    isLoading = false
  }
}

/**
 * Example SwiftUI view for the user profile
 */
public struct ProfileView: View {
  @State private var session: SessionData?
  @State private var isLoading: Bool = false
  @State private var errorMessage: String? = nil

  let authClient: BetterAuth
  let onSignOut: () -> Void

  public init(authClient: BetterAuth, onSignOut: @escaping () -> Void) {
    self.authClient = authClient
    self.onSignOut = onSignOut
  }

  public var body: some View {
    VStack(spacing: 16) {
      if isLoading {
        ProgressView("Loading profile...")
          .progressViewStyle(CircularProgressViewStyle())
      } else if let session = session {
        VStack(alignment: .leading, spacing: 16) {
          Text("Profile")
            .font(.largeTitle)
            .fontWeight(.bold)

          VStack(alignment: .leading, spacing: 8) {
            Text("Name: \(session.user.name ?? "N/A")")
              .font(.headline)

            Text("Email: \(session.user.email ?? "N/A")")
              .font(.headline)

            Text("User ID: \(session.user.id)")
              .font(.caption)

            if let emailVerified = session.user.emailVerified {
              Text("Email verified: \(emailVerified ? "Yes" : "No")")
                .font(.caption)
            }
          }
          .padding()
          //                    .background(Color(.systemGray6))
          .cornerRadius(8)

          Button(action: {
            Task {
              await signOut()
            }
          }) {
            Text("Sign Out")
              .fontWeight(.semibold)
              .foregroundColor(.white)
              .frame(maxWidth: .infinity)
          }
          .padding()
          .background(Color.red)
          .cornerRadius(8)
        }
      } else if let errorMessage = errorMessage {
        VStack {
          Text("Error loading profile")
            .font(.headline)

          Text(errorMessage)
            .foregroundColor(.red)
            .font(.caption)

          Button(action: {
            Task {
              await loadSession()
            }
          }) {
            Text("Retry")
              .fontWeight(.semibold)
              .foregroundColor(.white)
              .frame(maxWidth: .infinity)
          }
          .padding()
          .background(Color.blue)
          .cornerRadius(8)
        }
      }
    }
    .padding()
    .task {
      await loadSession()
    }
  }

  private func loadSession() async {
    isLoading = true
    errorMessage = nil

    do {
      session = try await authClient.getSession()
    } catch {
      errorMessage = error.localizedDescription

      // If unauthorized, sign out
      if case BetterAuthError.serverError(let statusCode) = error, statusCode == 401 {
        onSignOut()
      }
    }

    isLoading = false
  }

  private func signOut() async {
    isLoading = true

    do {
      try await authClient.signOut()
      onSignOut()
    } catch {
      errorMessage = error.localizedDescription
    }

    isLoading = false
  }
}

/**
 * Example SwiftUI view for authentication flow with automatic session management
 */
public struct AuthView: View {
  @State private var isSignedIn: Bool = false
  @State private var isLoading: Bool = true
  let authClient: BetterAuth

  public init(authClient: BetterAuth) {
    self.authClient = authClient
  }

  public var body: some View {
    Group {
      if isLoading {
        ProgressView("Checking session...")
      } else if isSignedIn {
        ProfileView(authClient: authClient) {
          isSignedIn = false
        }
      } else {
        SignInView(authClient: authClient) { _ in
          isSignedIn = true
        }
      }
    }
    .task {
      await checkSession()
    }
    .onAppear {
      setupObserver()
    }
  }

  private func checkSession() async {
    do {
      _ = try await authClient.getSession()
      isSignedIn = true
    } catch {
      isSignedIn = false
    }
    isLoading = false
  }

  private func setupObserver() {
    // Add observer for session changes
    Task {
      let _ = await authClient.addSessionObserver { session in
        Task { @MainActor in
          isSignedIn = session != nil
        }
      }
    }
  }
}

/**
 * A view for handling magic link verification
 */
@available(iOS 16.0, macOS 13.0, *)
public struct MagicLinkVerificationView: View {
  @State private var isLoading = true
  @State private var errorMessage: String? = nil
  @State private var isVerified = false

  let token: String
  let authClient: BetterAuth
  let onVerified: (SessionData) -> Void

  public init(token: String, authClient: BetterAuth, onVerified: @escaping (SessionData) -> Void) {
    self.token = token
    self.authClient = authClient
    self.onVerified = onVerified
  }

  public var body: some View {
    VStack(spacing: 20) {
      if isLoading {
        ProgressView("Verifying magic link...")
          .progressViewStyle(CircularProgressViewStyle())
      } else if isVerified {
        VStack(spacing: 16) {
          Image(systemName: "checkmark.circle.fill")
            .font(.system(size: 64))
            .foregroundColor(.green)

          Text("Successfully signed in!")
            .font(.title)
            .fontWeight(.bold)

          Text("You can close this page now.")
            .foregroundColor(.secondary)
        }
      } else if let errorMessage = errorMessage {
        VStack(spacing: 16) {
          Image(systemName: "xmark.circle.fill")
            .font(.system(size: 64))
            .foregroundColor(.red)

          Text("Verification Failed")
            .font(.title)
            .fontWeight(.bold)

          Text(errorMessage)
            .foregroundColor(.secondary)
            .multilineTextAlignment(.center)
        }
      }
    }
    .padding()
    .task {
      await verifyMagicLink()
    }
  }

  private func verifyMagicLink() async {
    do {
      let session = try await authClient.verifyMagicLink(token: token)
      isVerified = true
      onVerified(session)
    } catch {
      errorMessage = error.localizedDescription
    }

    isLoading = false
  }
}

/**
 * Custom SwiftUI view modifier to handle URL callbacks for OAuth authentication flows
 */
@available(iOS 16.0, macOS 13.0, *)
public struct BetterAuthURLHandler: ViewModifier {
  let authClient: BetterAuth
  let scheme: String
  @State private var magicLinkToken: String? = nil
  @State private var showMagicLinkVerification = false
  var onNavigate: ((String) -> Void)? = nil

  public init(authClient: BetterAuth, scheme: String, onNavigate: ((String) -> Void)? = nil) {
    self.authClient = authClient
    self.scheme = scheme
    self.onNavigate = onNavigate
  }

  public func body(content: Content) -> some View {
    ZStack {
      content
#if os(iOS)
        .onOpenURL { url in
          guard url.scheme == scheme else { return }

          // Use a Task to handle async auth callback
          Task {
            // Handle OAuth callback and get navigation information
            let (path, success) = await authClient.handleAuthCallback(url: url)
            if success {
              // Navigate to the destination path if authentication was successful
              await MainActor.run {
                onNavigate?(path)
              }
            }
          }

          // Handle magic link verification if present
          if let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
             let token = components.queryItems?.first(where: { $0.name == "token" })?.value {
            magicLinkToken = token
            showMagicLinkVerification = true
          }
        }
#endif

      // Show the verification view as a sheet when needed
      if showMagicLinkVerification, let token = magicLinkToken {
        MagicLinkVerificationView(token: token, authClient: authClient) { _ in
          showMagicLinkVerification = false
          magicLinkToken = nil
        }
#if os(iOS)
        .frame(width: 300, height: 300)
        .background(Color(.systemBackground))
        .cornerRadius(16)
        .shadow(radius: 10)
        .transition(.opacity)
#endif
      }
    }
  }
}

/**
 * Extension to easily apply the URL handler modifier
 */
public extension View {
  func handleBetterAuthURL(
    authClient: BetterAuth, 
    scheme: String,
    onNavigate: ((String) -> Void)? = nil
  ) -> some View {
    modifier(BetterAuthURLHandler(authClient: authClient, scheme: scheme, onNavigate: onNavigate))
  }
}

