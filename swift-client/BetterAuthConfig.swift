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
  
  /// Initialize with configuration
  /// - Parameters:
  ///   - baseURL: Base URL for the Better Auth server
  ///   - basePath: Base path for the API endpoints (defaults to "/api/auth")
  ///   - keychainServiceName: Keychain service name (defaults to "better-auth")
  ///   - keychainAccessGroup: Optional Keychain Access Group for sharing tokens
  ///   - callbackURLScheme: URL scheme for OAuth callback URLs (defaults to "better-auth")
  public init(
    baseURL: String,
    basePath: String? = "/api/auth",
    keychainServiceName: String = "better-auth",
    keychainAccessGroup: String? = nil,
    callbackURLScheme: String = "better-auth"
  ) {
    self.baseURL = baseURL
    self.basePath = basePath
    self.keychainServiceName = keychainServiceName // Store configured name
    self.keychainAccessGroup = keychainAccessGroup // Store configured group
    self.callbackURLScheme = callbackURLScheme
  }
}
