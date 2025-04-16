import Foundation

/**
 * Better Auth errors
 */
public enum BetterAuthError: Error, LocalizedError {
  case invalidURL
  case invalidResponse
  case serverError(statusCode: Int)
  case noData
  case apiError(message: String, code: String?)
  case flowRequiresRedirect
  case invalidRedirectURL
  
  public var errorDescription: String? {
    switch self {
      case .invalidURL:
        return "Invalid URL"
      case .invalidResponse:
        return "Invalid response"
      case .serverError(let statusCode):
        return "Server error: \(statusCode)"
      case .noData:
        return "No data received"
      case .apiError(let message, _):
        return message
      case .flowRequiresRedirect:
        return "This authentication flow requires a redirect"
      case .invalidRedirectURL:
        return "Invalid redirect URL"
    }
  }
}
