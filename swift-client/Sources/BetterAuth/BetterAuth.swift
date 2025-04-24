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
  public let config: BetterAuthConfig

  /// Session data
  public var session: SessionData?

  // --- Token Properties ---
  /// JWT token (Short-lived, In-Memory Only)
  private var jwtToken: String?
  /// JWT token expiration time (In-Memory Only)
  private var jwtTokenExpiration: Date?
  /// Decoded JWT token claims (In-Memory Only)
  private var jwtTokenClaims: [String: Any]?
  /// Refresh token (Long-lived, Persisted in Keychain)
  private var refreshToken: String?
  // --- End Token Properties ---

  /// Refresh token keychain key (Account name in keychain)
  private let refreshTokenKey = "refresh_token"
  // Removed: private let jwtTokenKey = "jwt_token"

  /// Initialize the Better Auth client with configuration
  /// - Parameter config: The configuration for the client
  public init(config: BetterAuthConfig) {
    self.config = config
    // Load ONLY the refresh token from keychain on init
    self.refreshToken = loadFromKeychain(key: refreshTokenKey)
    // jwtToken starts nil, will be fetched on demand
  }

  // MARK: - Session Management

  /// Get the current session using an authenticated request
  /// - Returns: The session data
  /// - Throws: An error if the request fails
  public func getSession() async throws -> SessionData {
    // Use the generic 'request' method which handles auth
    let result: SessionData = try await request(
      method: HTTPMethod.get,
      url: try Self.url(baseURL: config.baseURL, path: "\(config.basePath ?? "/api/auth")/get-session")
    )
    self.session = result // Update local session state
    return result
  }

  // MARK: - Authentication

  /// Sign in with email and password
  /// - Parameters:
  ///   - email: User's email
  ///   - password: User's password
  /// - Returns: The User object upon successful login. Session/refresh tokens handled internally.
  /// - Throws: An error if the request fails
  public func signInWithEmail(email: String, password: String) async throws -> User {
    let body: [String: Any] = [
      "email": email,
      "password": password
    ]
    // Use the base 'fetch' as sign-in might return tokens in headers/body
    // 'fetch' will handle saving the refresh token and updating in-memory JWT if provided.
    let response: SignInResponse = try await fetch(path: "/sign-in/email", method: HTTPMethod.post, body: body)

    // Refresh token (if sent via 'set-auth-token' header) is handled by `fetch`.
    // JWT token (if sent via 'set-auth-jwt' header) is handled by `fetch`.

    if response.redirect == true {
      throw BetterAuthError.flowRequiresRedirect
    }

    guard let user = response.user else {
      print("Error: Sign in response was successful but missing 'user' object.")
      throw BetterAuthError.invalidResponse
    }
    _ = try? await getSession()
    return user
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
    // Use base 'fetch' as this doesn't require prior auth
    let response: MagicLinkResponse = try await fetch(path: "/sign-in/magic-link", method: HTTPMethod.post, body: body)
    return response.status
  }

  /// Verify a magic link token
  /// - Parameters:
  ///   - token: The token from the magic link
  ///   - callbackURL: Optional callback URL
  /// - Returns: The session data
  /// - Throws: An error if verification fails
  public func verifyMagicLink(token: String, callbackURL: String? = nil) async throws {
    var path = "/magic-link/verify?token=\(token)"
    if let callbackURL = callbackURL {
      path += "&callbackURL=\(callbackURL)"
    }
    // Use base 'fetch'. This request might return tokens in headers upon success.
    let _: MagicLinkVerificationResponse = try await fetch(path: path, method: HTTPMethod.get)
    // Fetch session explicitly after verification to confirm success and get data
    _ = try await getSession()
  }

  /// Sign in with a social provider (prepares the URL)
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
    let cleanDestination = destination.starts(with: "/") ? String(destination.dropFirst()) : destination
    let encodedDestination = cleanDestination.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? cleanDestination
    let callbackURL = "\(config.callbackURLScheme):///\(encodedDestination)"

    var body: [String: Any] = [
      "provider": provider,
      "callbackURL": callbackURL
    ]

    if let options = options {
      for (key, value) in options {
        body[key] = value
      }
    }

    // Use base 'fetch' as this doesn't require prior auth
    let response: SocialAuthResponse = try await fetch(path: "/sign-in/social", method: HTTPMethod.post, body: body)
    if let url = URL(string: response.url) {
      return url
    } else {
      throw BetterAuthError.invalidRedirectURL
    }
  }

  // MARK: - Platform-specific social authentication methods
  // (authenticateWithSocial methods remain largely the same conceptually,
  //  they just call the updated signInWithSocial and handleAuthCallback)

#if os(iOS)
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
        Task { // Ensure async operations run in a Task
          if let error = error {
            continuation.resume(throwing: error)
            return
          }
          guard let callbackURL = callbackURL else {
            continuation.resume(throwing: BetterAuthError.authenticationFailed)
            return
          }
          let (_, success) = await self.handleAuthCallback(url: callbackURL) // handleAuthCallback saves refresh token
          if success {
            do {
              let session = try await self.getSession() // Now uses the new refresh token implicitly via request() -> getJWTToken() -> refresh
              continuation.resume(returning: (true, session))
            } catch {
              print("Error fetching session after social auth callback: \(error)")
              continuation.resume(returning: (true, nil)) // Success in auth, but session fetch failed
            }
          } else {
            continuation.resume(returning: (false, nil))
          }
        }
      }
      authSession.presentationContextProvider = presentationContextProvider
      authSession.prefersEphemeralWebBrowserSession = !config.enableSharedCookies
      if !authSession.start() {
        continuation.resume(throwing: BetterAuthError.authenticationFailed)
      }
    }
  }
#elseif os(macOS)
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
        Task { // Ensure async operations run in a Task
          if let error = error {
            continuation.resume(throwing: error)
            return
          }
          guard let callbackURL = callbackURL else {
            continuation.resume(throwing: BetterAuthError.authenticationFailed)
            return
          }
          let (_, success) = await self.handleAuthCallback(url: callbackURL) // handleAuthCallback saves refresh token
          if success {
            do {
              let session = try await self.getSession() // Now uses the new refresh token implicitly via request() -> getJWTToken() -> refresh
              continuation.resume(returning: (true, session))
            } catch {
              print("Error fetching session after social auth callback: \(error)")
              continuation.resume(returning: (true, nil)) // Success in auth, but session fetch failed
            }
          } else {
            continuation.resume(returning: (false, nil))
          }
        }
      }
      authSession.prefersEphemeralWebBrowserSession = !config.enableSharedCookies
      if !authSession.start() {
        continuation.resume(throwing: BetterAuthError.authenticationFailed)
      }
    }
  }
#else
  public func authenticateWithSocial(
    provider: String,
    destination: String = "/dashboard",
    options: [String: Any]? = nil,
    presentationContextProvider: ASWebAuthenticationPresentationContextProviding // Keep param for signature consistency if needed elsewhere
  ) async throws -> (success: Bool, session: SessionData?) {
    throw BetterAuthError.platformNotSupported
  }
#endif

  /// Handle the callback URL from social sign in
  /// - Parameter url: The callback URL
  /// - Returns: A tuple containing the destination path and a boolean indicating success
  public func handleAuthCallback(url: URL) async -> (path: String, success: Bool) {
    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
      return ("/", false)
    }

    let path = url.path.isEmpty ? "/" : url.path
    let queryItems = components.queryItems

    // Check for refresh token in query parameters (adjust param name if needed)
    // Prefer 'set-auth-token' if your backend uses that standard, otherwise check common names.
    let tokenParamName = "set-auth-token" // Or "token", "refresh_token", etc.
    if let tokenItem = queryItems?.first(where: { $0.name == tokenParamName }),
       let tokenValue = tokenItem.value {

      // Clear any old in-memory JWT state as we have a new refresh token
      self.jwtToken = nil
      self.jwtTokenExpiration = nil
      self.jwtTokenClaims = nil

      // Save the new refresh token
      self.refreshToken = tokenValue
      saveToKeychain(key: refreshTokenKey, value: tokenValue)

      // No need to fetch session here, just confirm token was received
      return (path, true)
    }

    // Handle potential error parameters from OAuth provider
    if let errorItem = queryItems?.first(where: { $0.name == "error" }) {
      let errorDesc = queryItems?.first(where: { $0.name == "error_description" })?.value
      print("OAuth Callback Error: \(errorItem.value ?? "Unknown") - \(errorDesc ?? "No description")")
      return (path, false)
    }

    print("OAuth Callback: Refresh token not found in query parameters.")
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
    // Use base 'fetch'. This request might return tokens in headers upon success.
    let sessionData: SessionData = try await fetch(path: "/sign-up/email", method: HTTPMethod.post, body: body)
    self.session = sessionData // Update local session state
    // Refresh token and JWT (if provided in headers) are handled by 'fetch'
    return sessionData
  }

  /// Sign out the current user
  /// - Throws: An error if the request fails
  public func signOut() async throws {
    // Use base 'fetch' - it will include the current refresh token for auth if needed by backend
    let _: EmptyResponse = try await fetch(path: "/sign-out", method: HTTPMethod.post)

    // Clear session and ALL tokens (memory and keychain)
    session = nil
    jwtToken = nil
    jwtTokenExpiration = nil
    jwtTokenClaims = nil
    refreshToken = nil // Clear in-memory refresh token

    // Clear refresh token from keychain
    deleteFromKeychain(key: refreshTokenKey)
    // Removed: deleteFromKeychain(key: jwtTokenKey)
  }

  // MARK: - JWT Token Management

  /// Check if the current in-memory JWT token is valid (exists and not expired within buffer)
  /// - Parameter bufferSeconds: Buffer time in seconds before expiration
  /// - Returns: True if valid, false otherwise
  private func isJWTTokenValid(bufferSeconds: TimeInterval = 30) -> Bool {
    guard jwtToken != nil, let expiration = jwtTokenExpiration else {
      return false // No token or expiration date
    }
    return expiration > Date().addingTimeInterval(bufferSeconds)
  }

  /// Get the claims from the current JWT token (decodes if necessary)
  /// - Returns: Dictionary of claims if token exists, nil otherwise
  public func getJWTClaims() -> [String: Any]? {
    if let claims = jwtTokenClaims {
      return claims // Return cached claims
    } else if let token = jwtToken {
      // Decode on-demand if claims aren't cached but token exists
      let claims = decodeJWT(token)
      jwtTokenClaims = claims // Cache the decoded claims
      return claims
    }
    return nil // No token available
  }

  /// Get a valid JWT token for API requests, refreshing if necessary.
  /// This is the primary method components should use to get a JWT.
  /// - Returns: The JWT token string
  /// - Throws: An error if refresh fails or no refresh token is available
  public func getJWTToken() async throws -> String {
    // 1. Check if the current in-memory token is valid
    if isJWTTokenValid() {
      return jwtToken! // We know it's non-nil due to the check
    }

    // 2. If not valid, attempt to refresh using the refresh token
    print("JWT token invalid or missing. Attempting refresh...")
    let response = try await performTokenRefresh() // This function handles the API call

    // 3. Update in-memory JWT state after successful refresh
    self.jwtToken = response.token
    self.decodeAndStoreJWTClaims(token: response.token) // Decode and store new claims/expiry

    print("Token refresh successful.")
    return response.token
  }

  /// Performs the network request to refresh the JWT using the stored refresh token.
  /// - Returns: The JWTResponse containing the new token.
  /// - Throws: An error if the refresh fails or no refresh token exists.
  private func performTokenRefresh() async throws -> JWTResponse {
    guard self.refreshToken != nil else {
      print("Error: Cannot refresh token, no refresh token available.")
      throw BetterAuthError.authenticationFailed // Or a more specific error like .missingRefreshToken
    }

    // Use the base 'fetch' method. It automatically includes the
    // current 'refreshToken' as the Bearer token in the Authorization header.
    print("Performing token refresh request...")
    do {
      let response: JWTResponse = try await fetch(path: "/token", method: HTTPMethod.get)
      return response
    } catch let error as BetterAuthError {
      // If refresh fails (e.g., 401 on /token), clear the bad refresh token and rethrow.
      print("Token refresh failed: \(error.localizedDescription). Clearing refresh token.")
      self.refreshToken = nil
      self.deleteFromKeychain(key: self.refreshTokenKey)
      // Also clear any potentially stale JWT info
      self.jwtToken = nil
      self.jwtTokenExpiration = nil
      self.jwtTokenClaims = nil
      throw error // Rethrow the original error
    } catch {
      // Catch other potential errors during fetch
      print("Unexpected error during token refresh: \(error)")
      throw error
    }
  }


  /// Decodes JWT claims and updates expiration date.
  /// - Parameter token: The JWT string.
  private func decodeAndStoreJWTClaims(token: String) {
    if let claims = decodeJWT(token) {
      self.jwtTokenClaims = claims
      if let expTimestamp = claims["exp"] as? TimeInterval {
        self.jwtTokenExpiration = Date(timeIntervalSince1970: expTimestamp)
        // print("Decoded JWT expiration: \(self.jwtTokenExpiration!)")
      } else {
        print("JWT 'exp' claim missing or invalid. Setting default expiration.")
        // Set a default short expiration if 'exp' is missing, e.g., 15 mins from now
        self.jwtTokenExpiration = Date().addingTimeInterval(15 * 60)
      }
    } else {
      print("Failed to decode JWT. Setting default expiration.")
      self.jwtTokenClaims = nil // Ensure claims are nil if decode fails
      self.jwtTokenExpiration = Date().addingTimeInterval(15 * 60) // Default expiration
    }
  }


  /// Decode a JWT token into claims (simple decode, no verification)
  /// - Parameter token: The JWT token to decode
  /// - Returns: Dictionary of claims or nil if decoding fails
  internal func decodeJWT(_ token: String) -> [String: Any]? { // Made internal for potential use in TokenManager later
    let segments = token.components(separatedBy: ".")
    guard segments.count >= 2 else { // Need at least header and payload
      print("Invalid JWT format: Incorrect number of segments.")
      return nil
    }
    guard let payloadData = base64UrlDecode(segments[1]) else {
      print("Invalid JWT format: Could not decode payload.")
      return nil
    }
    do {
      let json = try JSONSerialization.jsonObject(with: payloadData, options: [])
      return json as? [String: Any]
    } catch {
      print("Invalid JWT format: Payload is not valid JSON. Error: \(error)")
      return nil
    }
  }

  /// Decode base64url encoded string to Data
  /// - Parameter base64url: The base64url encoded string
  /// - Returns: Decoded data or nil if decoding fails
  private func base64UrlDecode(_ base64url: String) -> Data? {
    var base64 = base64url
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let length = base64.count
    let requiredLength = length + (4 - length % 4) % 4
    base64 = base64.padding(toLength: requiredLength, withPad: "=", startingAt: 0)
    return Data(base64Encoded: base64)
  }

  // MARK: - API Request Wrapper (Handles Auth)

  /// Makes an authenticated API request, handling token refresh and retries.
  /// - Parameters:
  ///   - method: The HTTP method (e.g., "GET", "POST").
  ///   - url: The full URL for the request.
  ///   - body: Optional request body dictionary.
  ///   - headers: Optional additional headers.
  ///   - retry: Internal flag to prevent infinite retries (should usually be true initially).
  /// - Returns: The decoded response of type T.
  /// - Throws: BetterAuthError or other network/decoding errors.
  public func request<T: Decodable>(
    method: String,
    url: URL,
    body: [String: Any]? = nil,
    headers: [String: String]? = nil,
    retry: Bool = true // Keep retry flag for internal use
  ) async throws -> T {

    // 1. Get a valid JWT token (handles refresh internally)
    //    Place this *inside* the do-catch to handle potential refresh errors.
    var token: String? = nil
    do {
      token = try await getJWTToken()
    } catch BetterAuthError.authenticationFailed {
      // If getJWTToken fails specifically because refresh token is missing/invalid,
      // rethrow immediately without attempting the request.
      print("Authentication required, but no valid refresh token available.")
      throw BetterAuthError.authenticationFailed // Re-throw the specific error
    } catch {
      // Handle other potential errors during token fetch
      print("Unexpected error during JWT token retrieval: \(error)")
      throw error // Rethrow other errors
    }

    // Ensure token was actually obtained (should be guaranteed by getJWTToken unless it threw)
    guard let validToken = token else {
      // This case should ideally be caught by getJWTToken throwing, but handle defensively.
      print("Error: Failed to obtain a valid JWT token for the request.")
      throw BetterAuthError.authenticationFailed
    }


    // 2. Prepare the request
    var request = URLRequest(url: url)
    request.httpMethod = method
    request.addValue("application/json", forHTTPHeaderField: "Content-Type")
    request.addValue("Bearer \(validToken)", forHTTPHeaderField: "Authorization") // Use the obtained valid token

    headers?.forEach { key, value in
      request.addValue(value, forHTTPHeaderField: key)
    }

    if let body = body {
      request.httpBody = try? JSONSerialization.data(withJSONObject: body)
    }

    // 3. Perform the request
    // print("Making authenticated request to \(url.absoluteString) with method \(method)")
    let (data, response) = try await URLSession.shared.data(for: request)

    guard let httpResponse = response as? HTTPURLResponse else {
      throw BetterAuthError.invalidResponse
    }

    // 4. Handle response codes and potential errors
    if httpResponse.statusCode >= 400 {
      // Check specifically for 401 Unauthorized
      if httpResponse.statusCode == 401 && retry {
        print("Received 401 Unauthorized. Clearing in-memory JWT and retrying request once.")
        // Clear ONLY the in-memory JWT state, forcing a refresh on retry
        self.jwtToken = nil
        self.jwtTokenExpiration = nil
        self.jwtTokenClaims = nil
        // Retry the request, setting retry to false
        return try await self.request(method: method, url: url, body: body, headers: headers, retry: false)
      } else {
        // Handle other errors (or 401 without retry)
        do {
          let errorResponse = try JSONDecoder().decode(ErrorResponse.self, from: data)
          print("API Error (\(httpResponse.statusCode)): \(errorResponse.message)")
          throw BetterAuthError.apiError(message: errorResponse.message, code: errorResponse.code)
        } catch {
          // If decoding ErrorResponse fails, throw a generic server error
          print("Server Error (\(httpResponse.statusCode)). Could not decode error response.")
          throw BetterAuthError.serverError(statusCode: httpResponse.statusCode)
        }
      }
    }

    // 5. Handle successful response (status < 400)
    // Check for tokens in headers (though less common for authenticated requests)
    if let newRefreshToken = httpResponse.value(forHTTPHeaderField: "set-auth-token") {
      print("Received new refresh token in authenticated response header.")
      self.refreshToken = newRefreshToken
      saveToKeychain(key: refreshTokenKey, value: newRefreshToken)
      // Clear old JWT as refresh token changed
      self.jwtToken = nil
      self.jwtTokenExpiration = nil
      self.jwtTokenClaims = nil
    }
    if let newJwtToken = httpResponse.value(forHTTPHeaderField: "set-auth-jwt") {
      if newJwtToken == self.jwtToken {
        print("JWT included in response header is same as current JWT stored in memory.")
      } else {
        print("Received new JWT in authenticated response header.")
        self.jwtToken = newJwtToken
        decodeAndStoreJWTClaims(token: newJwtToken)
      }
    }


    // Decode the successful response body
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    decoder.dateDecodingStrategy = .customBetterAuthDateFormatter()

    if data.isEmpty {
      if T.self == EmptyResponse.self {
        return EmptyResponse() as! T
      } else if T.self == Void.self {
        return () as! T
      } else {
        // If expecting data but got none, it's likely an error or unexpected response
        print("Warning: Expected decodable response of type \(T.self) but received empty data.")
        // Depending on strictness, you might throw here:
        // throw BetterAuthError.noData
        // Or return a default/empty state if appropriate for T (requires T to have an init or be Optional)
        // For now, let the decode attempt handle it (it will likely throw)
      }
    }

    do {
      let decoded = try decoder.decode(T.self, from: data)
      return decoded
    } catch let decodingError as DecodingError {
      print("Failed to decode successful response (\(httpResponse.statusCode)) to type \(T.self): \(decodingError)")
      throw decodingError // Re-throw the specific decoding error
    } catch {
      print("An unexpected error occurred during response decoding: \(error)")
      throw BetterAuthError.invalidResponse // Or a more specific decoding error
    }
  }


  // MARK: - HTTP Methods Enum
  public enum HTTPMethod {
    public static let get = "GET"
    public static let post = "POST"
    public static let put = "PUT"
    public static let delete = "DELETE"
    public static let patch = "PATCH"
  }

  // MARK: - URL Helper
  public static func url(baseURL: String, path: String) throws -> URL {
    // Ensure base URL doesn't end with / and path doesn't start with /
    let trimmedBase = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
    let trimmedPath = path.hasPrefix("/") ? String(path.dropFirst()) : path
    let endpoint = "\(trimmedBase)/\(trimmedPath)"

    guard let url = URL(string: endpoint) else {
      throw BetterAuthError.invalidURL
    }
    return url
  }

  // MARK: - Base Fetch (No Auth/Retry Logic)

  /// Make a base fetch request without automatic auth or retry logic.
  /// Used for initial sign-in/up calls or token refresh itself.
  /// Handles saving tokens received in headers.
  private func fetch<T: Decodable>(path: String, method: String, body: [String: Any]? = nil) async throws -> T {
    let baseURL = config.baseURL
    // Ensure basePath is handled correctly (add leading slash if missing, avoid double slash)
    let basePathSegment: String
    if let bp = config.basePath {
      basePathSegment = bp.hasPrefix("/") ? bp : "/\(bp)"
    } else {
      basePathSegment = "" // No base path
    }
    let fullPath = "\(basePathSegment)\(path)" // path should start with /
    let endpointURL = try Self.url(baseURL: baseURL, path: fullPath)

    var request = URLRequest(url: endpointURL)
    request.httpMethod = method
    request.addValue("application/json", forHTTPHeaderField: "Content-Type")

    // IMPORTANT: For calls like /token refresh, the REFRESH token needs to be the Bearer token.
    // This base 'fetch' method adds it if available.
    if let currentRefreshToken = self.refreshToken {
      request.addValue("Bearer \(currentRefreshToken)", forHTTPHeaderField: "Authorization")
      // print("Base fetch included Refresh Token in Authorization header for \(path)")
    } else {
      // print("Base fetch: No refresh token available for Authorization header for \(path)")
    }


    if let body = body {
      request.httpBody = try? JSONSerialization.data(withJSONObject: body)
    }

    // print("Base fetch request to \(endpointURL.absoluteString) with method \(method)")
    let (data, response) = try await URLSession.shared.data(for: request)

    guard let httpResponse = response as? HTTPURLResponse else {
      throw BetterAuthError.invalidResponse
    }

    // Check for tokens in response headers and update state
    if let newRefreshToken = httpResponse.value(forHTTPHeaderField: "set-auth-token") {
      print("Base fetch received 'set-auth-token' header.")
      self.refreshToken = newRefreshToken
      saveToKeychain(key: refreshTokenKey, value: newRefreshToken)
      // Clear potentially stale JWT if refresh token changed
      self.jwtToken = nil
      self.jwtTokenExpiration = nil
      self.jwtTokenClaims = nil
    }
    if let newJwtToken = httpResponse.value(forHTTPHeaderField: "set-auth-jwt") {
      print("Base fetch received 'set-auth-jwt' header.")
      self.jwtToken = newJwtToken
      decodeAndStoreJWTClaims(token: newJwtToken) // Update in-memory JWT state
    }

    // Check status code for errors
    if httpResponse.statusCode >= 400 {
      do {
        let errorResponse = try JSONDecoder().decode(ErrorResponse.self, from: data)
        print("Base fetch API Error (\(httpResponse.statusCode)) for \(path): \(errorResponse.message)")
        throw BetterAuthError.apiError(message: errorResponse.message, code: errorResponse.code)
      } catch {
        print("Base fetch Server Error (\(httpResponse.statusCode)) for \(path). Could not decode error response.")
        throw BetterAuthError.serverError(statusCode: httpResponse.statusCode)
      }
    }

    // Decode successful response
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    decoder.dateDecodingStrategy = .customBetterAuthDateFormatter()

    if data.isEmpty && T.self == EmptyResponse.self {
      return EmptyResponse() as! T
    }

    do {
      let decoded = try decoder.decode(T.self, from: data)
      return decoded
    } catch let decodingError as DecodingError {
      print("Base fetch failed to decode successful response (\(httpResponse.statusCode)) for \(path) to type \(T.self): \(decodingError)")
      throw decodingError
    } catch {
      print("Base fetch encountered an unexpected error during response decoding for \(path): \(error)")
      throw BetterAuthError.invalidResponse
    }
  }

  // MARK: - Keychain (Only for Refresh Token)

  private func buildKeychainQuery(key: String) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: config.keychainServiceName,
      kSecAttrAccount as String: key // Should always be refreshTokenKey now
    ]
    if let accessGroup = config.keychainAccessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    return query
  }

  @discardableResult
  private func saveToKeychain(key: String, value: String) -> Bool {
    // Ensure we only save the refresh token key
    guard key == refreshTokenKey, let data = value.data(using: .utf8) else {
      print("Error: Attempted to save invalid key or value to keychain.")
      return false
    }

    // Base query to identify the item
    let query = buildKeychainQuery(key: key)

    // Attributes to update or add
    let attributesToUpdate: [String: Any] = [
      kSecValueData as String: data,
      // Ensure accessibility is set on update too, in case it was different before
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    ]

    // Try to update existing item first
    var status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)

    if status == errSecItemNotFound {
      // Item not found, try to add it
      print("Keychain item for \(key) not found, attempting to add.")
      // Add the attributes to the query for the add operation
      var queryForAdd = query
      queryForAdd[kSecValueData as String] = data
      queryForAdd[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

      status = SecItemAdd(queryForAdd as CFDictionary, nil)
      if status == errSecSuccess {
        print("Keychain item for \(key) added successfully.")
      }
    } else if status == errSecSuccess {
      // Update successful
      // print("Keychain item for \(key) updated successfully.")
    } else {
      // Another error occurred during update
      print("Keychain update error for \(key): OSStatus \(status)")
    }

    // Return true only if the final status was success (either add or update)
    return status == errSecSuccess
  }

  private func loadFromKeychain(key: String) -> String? {
    // Ensure we only load the refresh token key
    guard key == refreshTokenKey else { return nil }

    var query = buildKeychainQuery(key: key)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    guard status == errSecSuccess,
          let data = result as? Data,
          let value = String(data: data, encoding: .utf8) else {
      if status != errSecItemNotFound {
        print("Keychain load error for \(key): OSStatus \(status)")
      }
      return nil
    }
    return value
  }

  @discardableResult
  private func deleteFromKeychain(key: String) -> Bool {
    // Ensure we only delete the refresh token key
    guard key == refreshTokenKey else { return false }

    let query = buildKeychainQuery(key: key)
    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
      print("Keychain delete error for \(key): OSStatus \(status)")
    }
    return status == errSecSuccess || status == errSecItemNotFound
  }

  // Internal getter for TokenManager (if implemented)
  internal func getCurrentRefreshToken() -> String? {
    return self.refreshToken
  }
}
