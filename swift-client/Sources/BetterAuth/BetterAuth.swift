import Foundation
import AuthenticationServices
import Security

/**
 * Main client for interacting with Better Auth server.
 */
@MainActor
@Observable
public final class BetterAuth {
  /// Base configuration
  public let config: BetterAuthConfig // Now holds keychain config too
  
  /// Session data
  private var session: SessionData?

  /// JWT token
  private var jwtToken: String?
  
  /// Refresh token
  private var refreshToken: String?

  /// JWT token keychain key (Account name in keychain)
  private let jwtTokenKey = "jwt_token"
  
  /// Refresh token keychain key (Account name in keychain)
  private let refreshTokenKey = "refresh_token"
  
  /// Initialize the Better Auth client with configuration
  /// - Parameter config: The configuration for the client
  public init(config: BetterAuthConfig) {
    self.config = config // Store the whole config
    
    self.refreshToken = loadFromKeychain(key: refreshTokenKey)
  }
  
  // MARK: - Session Management
  
  /// Get the current session
  /// - Returns: The session data
  /// - Throws: An error if the request fails
  public func getSession() async throws -> SessionData {
    let result: SessionData = try await fetchWithTokenRetry(path: "/get-session", method: "GET")
    session = result
    return result
  }
  
  // MARK: - Authentication
  
  /// Sign in with email and password
  /// - Parameters:
  ///   - email: User's email
  ///   - password: User's password
  /// - Returns: The session data
  /// - Throws: An error if the request fails
  public func signInWithEmail(email: String, password: String) async throws -> SessionData {
    let body: [String: Any] = [
      "email": email,
      "password": password
    ]
    let response: SignInResponse = try await fetch(path: "/sign-in/email", method: "POST", body: body)
    if let sessionData = response.session {
      session = sessionData
      return sessionData
    } else if response.redirect == true {
      // Handle redirect for OAuth flow - not applicable for this client
      throw BetterAuthError.flowRequiresRedirect
    } else {
      throw BetterAuthError.invalidResponse
    }
  }
  
  /// Sign in with magic link
  /// - Parameters:
  ///   - email: User's email
  ///   - name: Optional user name (used if signing up for the first time)
  ///   - callbackURL: URL to redirect after verification (optional)
  /// - Returns: True if the magic link was sent successfully
  /// - Throws: An error if the request fails
  public func signInWithMagicLink(email: String, name: String? = nil, callbackURL: String? = nil) async throws -> Bool {
    var body: [String: Any] = ["email": email]
    if let name = name {
      body["name"] = name
    }
    if let callbackURL {
      body["callbackURL"] = callbackURL
    }
    let response: MagicLinkResponse = try await fetch(path: "/sign-in/magic-link", method: "POST", body: body)
    return response.status
  }
  
  /// Verify a magic link token
  /// - Parameters:
  ///   - token: The token from the magic link
  ///   - callbackURL: Optional callback URL
  /// - Returns: The session data
  /// - Throws: An error if verification fails
  public func verifyMagicLink(token: String, callbackURL: String? = nil) async throws -> SessionData {
    var path = "/magic-link/verify?token=\(token)"
    if let callbackURL = callbackURL {
      path += "&callbackURL=\(callbackURL)"
    }
    let response: MagicLinkVerificationResponse = try await fetch(path: path, method: "GET")
    // Create a session data object from the verification response
    let sessionData = SessionData(
      user: response.user,
      session: Session(
        id: "",  // The token response doesn't include the full session object
        userId: response.user.id,
        expiresAt: Date().addingTimeInterval(24 * 60 * 60), // Default to 24 hours
        createdAt: Date(),
        updatedAt: Date(),
        lastUsedAt: nil,
        userAgent: nil,
        ip: nil
      )
    )
    self.session = sessionData
    return sessionData
  }
  
  /// Sign in with a social provider
  /// - Parameters:
  ///   - provider: The social provider to use (e.g., "github", "google")
  ///   - destination: The path to navigate to after successful authentication (e.g., "/dashboard")
  ///   - options: Additional provider-specific options (optional)
  /// - Returns: The URL to open for the OAuth flow
  /// - Throws: An error if the request fails
  public func signInWithSocial(
    provider: String, 
    destination: String = "/dashboard",
    options: [String: Any]? = nil
  ) async throws -> URL {
    // Ensure destination is properly encoded and doesn't start with a slash if it's provided
    let cleanDestination = destination.starts(with: "/") ? String(destination.dropFirst()) : destination
    let encodedDestination = cleanDestination.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? cleanDestination
    
    // Construct the callback URL that will handle the OAuth redirect
    // The format should be: scheme:///path (note the triple slash for deep links)
    let callbackURL = "\(config.callbackURLScheme):///\(encodedDestination)"
    
    var body: [String: Any] = [
      "provider": provider,
      "callbackURL": callbackURL
    ]
    
    // Add any additional options if provided
    if let options = options {
      for (key, value) in options {
        body[key] = value
      }
    }
    
    let response: SocialAuthResponse = try await fetch(path: "/sign-in/social", method: "POST", body: body)
    if let url = URL(string: response.url) {
      return url
    } else {
      throw BetterAuthError.invalidRedirectURL
    }
  }
  
  // MARK: - Platform-specific social authentication methods
  
  #if os(iOS)
  /// Initiates social sign-in with ASWebAuthenticationSession on iOS
  /// - Parameters:
  ///   - provider: The social provider to use (e.g., "github", "google")
  ///   - destination: The path to navigate to after successful authentication (e.g., "/dashboard")
  ///   - options: Additional provider-specific options (optional)
  ///   - presentationContextProvider: Context provider for iOS (required for iOS)
  /// - Returns: A tuple containing a success flag and session data if successful
  /// - Throws: An error if the request fails
  public func authenticateWithSocial(
    provider: String,
    destination: String = "/dashboard",
    options: [String: Any]? = nil,
    presentationContextProvider: ASWebAuthenticationPresentationContextProviding
  ) async throws -> (success: Bool, session: SessionData?) {
    let url = try await signInWithSocial(provider: provider, destination: destination, options: options)
    
    return try await withCheckedThrowingContinuation { continuation in
      let authSession = ASWebAuthenticationSession(
        url: url,
        callbackURLScheme: config.callbackURLScheme
      ) { callbackURL, error in
        if let error = error {
          continuation.resume(throwing: error)
          return
        }
        
        guard let callbackURL = callbackURL else {
          continuation.resume(throwing: BetterAuthError.authenticationFailed)
          return
        }
        
        // Use Task here since we're in a closure
        Task {
          let (_, success) = await self.handleAuthCallback(url: callbackURL)
          if success {
            // Try to get session data
            do {
              let session = try await self.getSession()
              continuation.resume(returning: (true, session))
            } catch {
              continuation.resume(returning: (true, nil))
            }
          } else {
            continuation.resume(returning: (false, nil))
          }
        }
      }
      
      // Set presentation context provider for iOS
      authSession.presentationContextProvider = presentationContextProvider
      
      // Configure ephemeral session based on config
      authSession.prefersEphemeralWebBrowserSession = !config.enableSharedCookies
      
      if !authSession.start() {
        continuation.resume(throwing: BetterAuthError.authenticationFailed)
      }
    }
  }
  #elseif os(macOS)
  /// Initiates social sign-in with ASWebAuthenticationSession on macOS
  /// - Parameters:
  ///   - provider: The social provider to use (e.g., "github", "google")
  ///   - destination: The path to navigate to after successful authentication (e.g., "/dashboard")
  ///   - options: Additional provider-specific options (optional)
  /// - Returns: A tuple containing a success flag and session data if successful
  /// - Throws: An error if the request fails
  public func authenticateWithSocial(
    provider: String,
    destination: String = "/dashboard",
    options: [String: Any]? = nil
  ) async throws -> (success: Bool, session: SessionData?) {
    let url = try await signInWithSocial(provider: provider, destination: destination, options: options)
    
    return try await withCheckedThrowingContinuation { continuation in
      let authSession = ASWebAuthenticationSession(
        url: url,
        callbackURLScheme: config.callbackURLScheme
      ) { callbackURL, error in
        if let error = error {
          continuation.resume(throwing: error)
          return
        }
        
        guard let callbackURL = callbackURL else {
          continuation.resume(throwing: BetterAuthError.authenticationFailed)
          return
        }
        
        // Use Task here since we're in a closure
        Task {
          do {
            let (_, success) = await self.handleAuthCallback(url: callbackURL)
            
            if success {
              // Try to get session data
              do {
                let session = try await self.getSession()
                continuation.resume(returning: (true, session))
              } catch {
                continuation.resume(returning: (true, nil))
              }
            } else {
              continuation.resume(returning: (false, nil))
            }
          } catch {
            continuation.resume(throwing: error)
          }
        }
      }
      
      // Configure ephemeral session based on config
      authSession.prefersEphemeralWebBrowserSession = !config.enableSharedCookies
      
      if !authSession.start() {
        continuation.resume(throwing: BetterAuthError.authenticationFailed)
      }
    }
  }
  #else
  /// Initiates social sign-in with ASWebAuthenticationSession
  /// - Parameters:
  ///   - provider: The social provider to use (e.g., "github", "google")
  ///   - destination: The path to navigate to after successful authentication (e.g., "/dashboard")
  ///   - options: Additional provider-specific options (optional)
  ///   - presentationContextProvider: Context provider for iOS (required for iOS)
  /// - Returns: A tuple containing a success flag and session data if successful
  /// - Throws: An error if the request fails
  public func authenticateWithSocial(
    provider: String,
    destination: String = "/dashboard",
    options: [String: Any]? = nil,
    presentationContextProvider: ASWebAuthenticationPresentationContextProviding
  ) async throws -> (success: Bool, session: SessionData?) {
    // For platforms other than iOS and macOS
    throw BetterAuthError.platformNotSupported
  }
  #endif
  
  /// Handle the callback URL from social sign in
  /// - Parameter url: The callback URL
  /// - Returns: A tuple containing the destination path and a boolean indicating success
  /// - Throws: An error if session retrieval fails
  public func handleAuthCallback(url: URL) async -> (path: String, success: Bool) {
    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
      return ("/", false)
    }
    
    // Extract the path from the URL to determine where to navigate
    // The path will be the part after the scheme:/// in the URL
    let path = url.path.isEmpty ? "/" : url.path
    
    // Extract query parameters if present
    let queryItems = components.queryItems
    
    // Check for session token or cookie in the query parameters
    if let tokenItem = queryItems?.first(where: { $0.name == "token" || $0.name == "cookie" }),
       let token = tokenItem.value {
      self.refreshToken = token
      saveToKeychain(key: refreshTokenKey, value: token)
      
      // Fetch the user session
      do {
        let _ = try await getSession()
        return (path, true)
      } catch {
        return (path, false)
      }
    }
    
    return (path, false)
  }
  
  /// Sign up with email and password
  /// - Parameters:
  ///   - email: User's email
  ///   - password: User's password
  ///   - name: User's name
  /// - Returns: The session data
  /// - Throws: An error if the request fails
  public func signUpWithEmail(email: String, password: String, name: String) async throws -> SessionData {
    let body: [String: Any] = [
      "email": email,
      "password": password,
      "name": name
    ]
    let sessionData: SessionData = try await fetch(path: "/sign-up/email", method: "POST", body: body)
    session = sessionData
    return sessionData
  }
  
  /// Sign out the current user
  /// - Throws: An error if the request fails
  public func signOut() async throws {
    let _: EmptyResponse = try await fetch(path: "/sign-out", method: "POST")
    
    // Clear session and tokens
    session = nil
    jwtToken = nil
    jwtTokenExpiration = nil
    jwtTokenClaims = nil
    refreshToken = nil
    
    // Clear keychain
    deleteFromKeychain(key: jwtTokenKey)
    deleteFromKeychain(key: refreshTokenKey)
  }
  
  // MARK: - JWT Token Management
  
  /// JWT token expiration time
  private var jwtTokenExpiration: Date?
  
  /// Storage for decoded JWT token claims
  private var jwtTokenClaims: [String: Any]?
  
  // MARK: - API Request Wrapper
  
  /// Makes an authenticated API request
  /// - Parameters:
  ///   - method: The HTTP method to use (GET, POST, PUT, DELETE)
  ///   - url: The URL to request
  ///   - body: Optional request body as dictionary
  ///   - headers: Additional headers to include
  ///   - retry: Whether to automatically retry on 401 error (default: true)
  /// - Returns: The decoded response of type T
  /// - Throws: An error if the request fails
  public func request<T: Decodable>(
    method: String,
    url: URL,
    body: [String: Any]? = nil,
    headers: [String: String]? = nil,
    retry: Bool = true
  ) async throws -> T {
    
    do {
      // Get a valid JWT token for the request
      let token = try await getJWTToken()
      
      // Prepare request
      var request = URLRequest(url: url)
      request.httpMethod = method
      request.addValue("application/json", forHTTPHeaderField: "Content-Type")
      request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
      
      // Add custom headers if provided
      headers?.forEach { key, value in
        request.addValue(value, forHTTPHeaderField: key)
      }
      
      // Add body if provided
      if let body = body {
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
      }
      
      // Perform the request
      let (data, response) = try await URLSession.shared.data(for: request)
      
      guard let httpResponse = response as? HTTPURLResponse else {
        throw BetterAuthError.invalidResponse
      }
      
      // Handle error responses
      if httpResponse.statusCode >= 400 {
        do {
          let errorResponse = try JSONDecoder().decode(ErrorResponse.self, from: data)
          throw BetterAuthError.apiError(message: errorResponse.message, code: errorResponse.code)
        } catch {
          if let decodingError = error as? DecodingError {
            throw decodingError
          } else {
            throw BetterAuthError.serverError(statusCode: httpResponse.statusCode)
          }
        }
      }
      
      let decoder = JSONDecoder()
      decoder.keyDecodingStrategy = .convertFromSnakeCase
      
      // Handle empty responses for Void or EmptyResponse return types
      if data.isEmpty {
        if T.self == EmptyResponse.self {
          return EmptyResponse() as! T
        } else if T.self == Void.self {
          return () as! T
        }
      }
      
      // Decode the response
      return try decoder.decode(T.self, from: data)
      
    } catch BetterAuthError.serverError(let statusCode) where statusCode == 401 && retry {
      // Clear JWT token and try again if retry is enabled
      jwtToken = nil
      jwtTokenExpiration = nil
      jwtTokenClaims = nil
      
      // Retry once without retry flag to prevent infinite recursion
      return try await request(
        method: method,
        url: url,
        body: body,
        headers: headers,
        retry: false
      )
    }
  }
  
  // MARK: - HTTP Methods
  
  /// HTTP method constants
  public enum HTTPMethod {
    public static let get = "GET"
    public static let post = "POST"
    public static let put = "PUT"
    public static let delete = "DELETE"
    public static let patch = "PATCH"
  }
  
  /// Create a URL by appending a path to a base URL
  /// - Parameters:
  ///   - baseURL: The base URL as a string
  ///   - path: The path to append
  /// - Returns: The constructed URL
  /// - Throws: An error if the URL is invalid
  public static func url(baseURL: String, path: String) throws -> URL {
    let endpoint = baseURL + path
    
    guard let url = URL(string: endpoint) else {
      throw BetterAuthError.invalidURL
    }
    
    return url
  }
  
  /// Check if the current JWT token is valid
  /// - Parameter bufferSeconds: Buffer time in seconds before expiration to consider token invalid
  /// - Returns: True if token exists and is not expired, false otherwise
  public func validateJWTToken(bufferSeconds: TimeInterval = 30) -> String? {
    guard let token = jwtToken, let expiration = jwtTokenExpiration, expiration > Date().addingTimeInterval(bufferSeconds) else {
      return nil
    }
    return token
  }
  
  /// Get the claims from the current JWT token
  /// - Returns: Dictionary of claims if token exists and can be decoded, nil otherwise
  public func getJWTClaims() -> [String: Any]? {
    if let claims = jwtTokenClaims {
      return claims
    } else if let token = jwtToken {
      // Try to decode on-demand if we have a token but no cached claims
      let claims = decodeJWT(token)
      jwtTokenClaims = claims
      return claims
    }
    return nil
  }
  
  /// Get a JWT token for API requests
  /// - Returns: The JWT token
  /// - Throws: An error if the request fails
  public func getJWTToken() async throws -> String {
    // If we have a cached token, check if it's still valid
    if let jwtToken = validateJWTToken() {
      // Return the cached token if it's not expired (including buffer period)s
      return jwtToken
    }
    // Token is expired or doesn't exist, get a new one
    let response: JWTResponse = try await fetchWithTokenRetry(path: "/token", method: "GET")
    jwtToken = response.token
    // Try to decode and store the expiration time
    if let claims = decodeJWT(response.token) {
      jwtTokenClaims = claims
      if let expTimestamp = claims["exp"] as? TimeInterval {
        jwtTokenExpiration = Date(timeIntervalSince1970: expTimestamp)
      } else {
        // If exp claim is missing, default to 15 minutes
        jwtTokenExpiration = Date().addingTimeInterval(15 * 60)
      }
    }
    return response.token
  }
  
  /// Decode a JWT token into claims
  /// - Parameter token: The JWT token to decode
  /// - Returns: Dictionary of claims or nil if decoding fails
  private func decodeJWT(_ token: String) -> [String: Any]? {
    let segments = token.components(separatedBy: ".")
    guard segments.count == 3,
          let payload = base64UrlDecode(segments[1]),
          let json = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
      return nil
    }
    return json
  }
  
  /// Decode base64url encoded string to Data
  /// - Parameter base64url: The base64url encoded string
  /// - Returns: Decoded data or nil if decoding fails
  private func base64UrlDecode(_ base64url: String) -> Data? {
    var base64 = base64url
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    // Add padding if needed
    if base64.count % 4 != 0 {
      base64.append(String(repeating: "=", count: 4 - base64.count % 4))
    }
    return Data(base64Encoded: base64)
  }
  
  // MARK: - Networking
  
  /// Make a fetch request with JSON response
  /// - Parameters:
  ///   - path: The path to request
  ///   - method: The HTTP method to use
  ///   - body: The request body
  /// - Returns: The decoded response
  /// - Throws: An error if the request fails
  private func fetch<T: Decodable>(path: String, method: String, body: [String: Any]? = nil) async throws -> T {
    let baseURL = config.baseURL
    let endpoint = "\(baseURL)\(config.basePath ?? "/api/auth")\(path)"
    
    guard let url = URL(string: endpoint) else {
      throw BetterAuthError.invalidURL
    }
    
    var request = URLRequest(url: url)
    request.httpMethod = method
    request.addValue("application/json", forHTTPHeaderField: "Content-Type")
    
    // Add the refresh token as a bearer token if available
    if let refreshToken {
      request.addValue("Bearer \(refreshToken)", forHTTPHeaderField: "Authorization")
    }
    
    // Add the body if provided
    if let body = body {
      request.httpBody = try JSONSerialization.data(withJSONObject: body)
    }
    
    let (data, response) = try await URLSession.shared.data(for: request)
    
    guard let httpResponse = response as? HTTPURLResponse else {
      throw BetterAuthError.invalidResponse
    }
    
    // Check for token in response headers
    if let authToken = httpResponse.value(forHTTPHeaderField: "set-auth-token") {
      self.refreshToken = authToken
      saveToKeychain(key: refreshTokenKey, value: authToken)
    }
    
    if let jwtToken = httpResponse.value(forHTTPHeaderField: "set-auth-jwt") {
      self.jwtToken = jwtToken
      
      // Parse and store the JWT token expiration
      if let claims = decodeJWT(jwtToken) {
        jwtTokenClaims = claims
        if let expTimestamp = claims["exp"] as? TimeInterval {
          jwtTokenExpiration = Date(timeIntervalSince1970: expTimestamp)
        } else {
          // If exp claim is missing, default to 15 minutes
          jwtTokenExpiration = Date().addingTimeInterval(15 * 60)
        }
      }
    }
    
    // Check status code
    if httpResponse.statusCode >= 400 {
      do {
        let errorResponse = try JSONDecoder().decode(ErrorResponse.self, from: data)
        throw BetterAuthError.apiError(message: errorResponse.message, code: errorResponse.code)
      } catch {
        if let decodingError = error as? DecodingError {
          throw decodingError
        } else {
          throw BetterAuthError.serverError(statusCode: httpResponse.statusCode)
        }
      }
    }
    
    // Special case for empty responses
    if data.isEmpty && T.self == EmptyResponse.self {
      return EmptyResponse() as! T
    }
    
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    let decoded = try decoder.decode(T.self, from: data)
    return decoded
  }
  
  /// Make a fetch request with token refresh on 401
  /// - Parameters:
  ///   - path: The path to request
  ///   - method: The HTTP method to use
  ///   - body: The request body
  /// - Returns: The decoded response
  /// - Throws: An error if the request fails
  private func fetchWithTokenRetry<T: Decodable>(path: String, method: String, body: [String: Any]? = nil) async throws -> T {
    do {
      return try await fetch(path: path, method: method, body: body)
    } catch BetterAuthError.serverError(let statusCode) where statusCode == 401 {
      // Token expired, clear it and retry
      jwtToken = nil
      jwtTokenExpiration = nil
      jwtTokenClaims = nil
      return try await fetch(path: path, method: method, body: body)
    }
  }
  
  // MARK: - Keychain
  
  /// Builds the base query dictionary for keychain operations.
  /// - Parameter key: The account key (e.g., "refresh_token").
  /// - Returns: A dictionary for keychain queries.
  private func buildKeychainQuery(key: String) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      // Use the configured service name
      kSecAttrService as String: config.keychainServiceName,
      kSecAttrAccount as String: key
    ]
    // Add the access group if it's configured
    if let accessGroup = config.keychainAccessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    return query
  }
  
  /// Save a value to the keychain
  /// - Parameters:
  ///   - key: The key (account) to save under
  ///   - value: The value to save
  /// - Returns: True if the save was successful
  @discardableResult
  private func saveToKeychain(key: String, value: String) -> Bool {
    guard let data = value.data(using: .utf8) else {
      return false
    }
    
    // Build the base query using the helper
    var query = buildKeychainQuery(key: key)
    
    // First delete any existing item matching the query
    SecItemDelete(query as CFDictionary)
    
    // Add the value data for the save operation
    query[kSecValueData as String] = data
    // Recommended: Set accessibility to only be available when unlocked
    query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    
    // Add the new item
    let status = SecItemAdd(query as CFDictionary, nil)
    if status != errSecSuccess {
      print("Keychain save error: \(status)") // Added basic logging
    }
    return status == errSecSuccess
  }
  
  /// Load a value from the keychain
  /// - Parameter key: The key (account) to load
  /// - Returns: The value if found, nil otherwise
  private func loadFromKeychain(key: String) -> String? {
    // Build the base query using the helper
    var query = buildKeychainQuery(key: key)
    
    // Specify what we want back
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    
    guard status == errSecSuccess,
          let data = result as? Data,
          let value = String(data: data, encoding: .utf8) else {
      if status != errSecItemNotFound {
        print("Keychain load error: \(status)") // Added basic logging
      }
      return nil
    }
    
    return value
  }
  
  /// Delete a value from the keychain
  /// - Parameter key: The key (account) to delete
  /// - Returns: True if the delete was successful or item wasn't found
  @discardableResult
  private func deleteFromKeychain(key: String) -> Bool {
    // Build the base query using the helper
    let query = buildKeychainQuery(key: key)
    
    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
      print("Keychain delete error: \(status)")
    }
    // Return true if deleted successfully OR if it wasn't there to begin with
    return status == errSecSuccess || status == errSecItemNotFound
  }
}
