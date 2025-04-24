import Foundation
import AuthenticationServices

@MainActor
class WebAuthPresenter: NSObject, ASWebAuthenticationPresentationContextProviding {

  private let callbackURLScheme: String
  private let prefersEphemeralSession: Bool
  private var authSession: ASWebAuthenticationSession?
  // Store the continuation to bridge the callback with async/await
  private var continuation: CheckedContinuation<URL, Error>?

  init(callbackURLScheme: String, prefersEphemeralSession: Bool) {
    self.callbackURLScheme = callbackURLScheme
    self.prefersEphemeralSession = prefersEphemeralSession
    super.init()
  }

  /// Starts the web authentication flow.
  /// - Parameter url: The authentication URL provided by the backend.
  /// - Returns: The callback URL received upon successful authentication.
  /// - Throws: An error if the authentication fails or is cancelled.
  func authenticate(with url: URL) async throws -> URL {
    // Use withCheckedThrowingContinuation to bridge the callback-based API
    try await withCheckedThrowingContinuation { continuation in
      // Store the continuation to be resumed later by the callback
      self.continuation = continuation

      // Create the ASWebAuthenticationSession
      let session = ASWebAuthenticationSession(
        url: url,
        callbackURLScheme: self.callbackURLScheme
      ) { [weak self] callbackURL, error in
        guard let self = self else { return } // Avoid retain cycles

        if let error = error {
          // If an error occurred, resume the continuation throwing the error
          self.continuation?.resume(throwing: error)
        } else if let callbackURL = callbackURL {
          // If successful, resume the continuation returning the callback URL
          self.continuation?.resume(returning: callbackURL)
        } else {
          // If both are nil (shouldn't typically happen), resume with a failure
          self.continuation?.resume(throwing: BetterAuthError.authenticationFailed)
        }
        // Clean up: nil out the continuation and session after resuming
        self.continuation = nil
        self.authSession = nil
      }

      self.authSession = session // Keep a reference to the session

      // Set presentation context provider for iOS/macOS modal presentation
#if os(iOS) || os(macOS)
      session.presentationContextProvider = self
#endif

      // Set preference for ephemeral session (private browsing)
      session.prefersEphemeralWebBrowserSession = self.prefersEphemeralSession

      // Start the session
      // Dispatch back to main thread if start() needs it, though ASWebAuthenticationSession usually handles this.
      // Using @MainActor on the class helps ensure this context.
      if !session.start() {
        // If starting the session fails immediately, resume with an error
        continuation.resume(throwing: BetterAuthError.authenticationFailed)
        // Clean up if start fails
        self.continuation = nil
        self.authSession = nil
      }
    }
  }

  // MARK: - ASWebAuthenticationPresentationContextProviding

#if os(iOS) || os(macOS)
  // Provide the presentation anchor (window) for the authentication session UI
  func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
    // Return the most relevant window. For simplicity, using a default anchor.
    // In a real app, you might find the key window:
    // return UIApplication.shared.connectedScenes.compactMap { ($0 as? UIWindowScene)?.keyWindow }.first ?? ASPresentationAnchor() // iOS Example
    return ASPresentationAnchor()
  }
#endif
}
