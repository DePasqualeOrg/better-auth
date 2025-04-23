import Foundation

/**
 * Configuration for Better Auth client
 */
public struct BetterAuthConfig {
  /// Base URL for the Better Auth server
  public let baseURL: String
  
  /// Base path for the API endpoints (defaults to "/api/auth")
  public let basePath: String?
  
  /// Keychain service name used for storing tokens. Defaults to "better-auth".
  /// Customize this if you need multiple BetterAuth instances potentially sharing
  /// the same access group, or if you have specific naming requirements.
  public let keychainServiceName: String
  
  /// Optional Keychain Access Group. If set, tokens will be stored in this group,
  /// allowing sharing between apps with the same Team ID and this entitlement.
  /// If nil (default), tokens are stored in the app's default keychain scope.
  public let keychainAccessGroup: String?
  
  /// URL scheme for OAuth callback URLs (e.g., "better-auth")
  public let callbackURLScheme: String
  
  /// Whether to share cookies with Safari for single sign-on capabilities.
  /// When true, if the user is already signed in to providers like Google or GitHub in Safari,
  /// they may not need to re-enter credentials during social sign-in.
  /// Default is true for better user experience.
  public let enableSharedCookies: Bool
  
  /// Initialize with configuration
  /// - Parameters:
  ///   - baseURL: Base URL for the Better Auth server
  ///   - basePath: Base path for the API endpoints (defaults to "/api/auth")
  ///   - keychainServiceName: Keychain service name (defaults to "better-auth")
  ///   - keychainAccessGroup: Optional Keychain Access Group for sharing tokens
  ///   - callbackURLScheme: URL scheme for OAuth callback URLs (defaults to "better-auth")
  ///   - enableSharedCookies: Whether to share cookies with Safari for SSO (defaults to true)
  public init(
    baseURL: String,
    basePath: String? = "/api/auth",
    keychainServiceName: String = "better-auth",
    keychainAccessGroup: String? = nil,
    callbackURLScheme: String = "better-auth",
    enableSharedCookies: Bool = true
  ) {
    self.baseURL = baseURL
    self.basePath = basePath
    self.keychainServiceName = keychainServiceName
    self.keychainAccessGroup = keychainAccessGroup
    self.callbackURLScheme = callbackURLScheme
    self.enableSharedCookies = enableSharedCookies
  }
}
