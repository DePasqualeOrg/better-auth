import Foundation

/**
 * User model
 */
public struct User: Codable {
  public let id: String
  public let email: String?
  public let name: String?
  public let emailVerified: Bool?
  public let image: String?
  public let createdAt: Date
  public let updatedAt: Date
}

/**
 * Session model
 */
public struct Session: Codable {
  public let id: String
  public let userId: String
  public let expiresAt: Date
  public let createdAt: Date
  public let updatedAt: Date
  public let lastUsedAt: Date?
  public let userAgent: String?
  public let ip: String?
}

/**
 * Session data that's returned by the server
 */
public struct SessionData: Codable {
  public let user: User
  public let session: Session
}

/**
 * Sign-in response model
 */
public struct SignInResponse: Codable {
  public let redirect: Bool?
  public let url: String?
  public let session: SessionData?
}

/**
 * Social auth response model
 */
public struct SocialAuthResponse: Codable {
  public let redirect: Bool
  public let url: String
}

/**
 * Magic link response model
 */
public struct MagicLinkResponse: Codable {
  public let status: Bool
}

/**
 * Magic link verification response model
 */
public struct MagicLinkVerificationResponse: Codable {
  public let token: String
  public let user: User
}

/**
 * JWT token response
 */
public struct JWTResponse: Codable {
  public let token: String
}

/**
 * Error response from the server
 */
public struct ErrorResponse: Codable {
  public let message: String
  public let code: String?
}

/**
 * Empty response for endpoints that don't return data
 */
public struct EmptyResponse: Codable {}
