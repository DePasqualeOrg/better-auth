import Foundation
import Security

/**
 * Main client for interacting with Better Auth server.
 */
public actor BetterAuth {
    
    /// Base configuration
    private let config: BetterAuthConfig
    
    /// Session data
    private var session: SessionData?
    
    /// JWT token
    private var jwtToken: String?
    
    /// Refresh token
    private var refreshToken: String?
    
    /// Session observers
    private var sessionObservers: [UUID: @Sendable (SessionData?) -> Void] = [:]
    
    /// Keychain service name for storing tokens
    private let keychainServiceName = "better-auth"
    
    /// JWT token keychain key
    private let jwtTokenKey = "jwt_token"
    
    /// Refresh token keychain key
    private let refreshTokenKey = "refresh_token"
    
    /// Initialize the Better Auth client with configuration
    /// - Parameter config: The configuration for the client
    public init(config: BetterAuthConfig) {
        self.config = config
        
        // Load refresh token from keychain
        self.refreshToken = loadFromKeychain(key: refreshTokenKey)
    }
    
    // MARK: - Session Management
    
    /// Add a session observer
    /// - Parameter observer: The observer closure
    /// - Returns: An observer ID that can be used to remove the observer
    @discardableResult
    public func addSessionObserver(_ observer: @escaping @Sendable (SessionData?) -> Void) -> UUID {
        let id = UUID()
        sessionObservers[id] = observer
        
        // Call the observer with the current session
        observer(session)
        
        return id
    }
    
    /// Remove a session observer
    /// - Parameter id: The observer ID to remove
    public func removeSessionObserver(id: UUID) {
        sessionObservers.removeValue(forKey: id)
    }
    
    /// Notify session observers of changes
    private func notifySessionObservers() {
        let currentSession = session
        for observer in sessionObservers.values {
            Task { @MainActor in
                observer(currentSession)
            }
        }
    }
    
    /// Get the current session
    /// - Returns: The session data
    /// - Throws: An error if the request fails
    public func getSession() async throws -> SessionData {
        let result: SessionData = try await fetchWithTokenRetry(path: "/get-session", method: "GET")
        session = result
        notifySessionObservers()
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
            notifySessionObservers()
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
        
        if let callbackURL = callbackURL {
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
        notifySessionObservers()
        return sessionData
    }
    
    /// Sign in with a social provider
    /// - Parameter provider: The social provider to use
    /// - Returns: The URL to open for the OAuth flow
    /// - Throws: An error if the request fails
    public func signInWithSocial(provider: String) async throws -> URL {
        let body: [String: Any] = [
            "provider": provider,
            "callbackURL": "better-auth://auth-callback"
        ]
        
        let response: SocialAuthResponse = try await fetch(path: "/sign-in/social", method: "POST", body: body)
        
        if let url = URL(string: response.url) {
            return url
        } else {
            throw BetterAuthError.invalidRedirectURL
        }
    }
    
    /// Handle the callback URL from social sign in
    /// - Parameter url: The callback URL
    /// - Returns: True if the URL was handled, false otherwise
    public func handleAuthCallback(url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              let queryItems = components.queryItems else {
            return false
        }
        
        // Check for session token
        if let sessionTokenItem = queryItems.first(where: { $0.name == "token" }),
           let token = sessionTokenItem.value {
            self.refreshToken = token
            saveToKeychain(key: refreshTokenKey, value: token)
            
            // Fetch the user session
            Task {
                try? await getSession()
            }
            
            return true
        }
        
        return false
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
        notifySessionObservers()
        return sessionData
    }
    
    /// Sign out the current user
    /// - Throws: An error if the request fails
    public func signOut() async throws {
        let _: EmptyResponse = try await fetch(path: "/sign-out", method: "POST")
        
        // Clear session and tokens
        session = nil
        jwtToken = nil
        refreshToken = nil
        
        // Clear keychain
        deleteFromKeychain(key: jwtTokenKey)
        deleteFromKeychain(key: refreshTokenKey)
        
        notifySessionObservers()
    }
    
    // MARK: - JWT Token Management
    
    /// Get a JWT token for API requests
    /// - Returns: The JWT token
    /// - Throws: An error if the request fails
    public func getJWTToken() async throws -> String {
        if let jwtToken = jwtToken {
            // Return the cached JWT token
            return jwtToken
        }
        
        let response: JWTResponse = try await fetchWithTokenRetry(path: "/token", method: "GET")
        jwtToken = response.token
        return response.token
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
        if let refreshToken = refreshToken {
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
            return try await fetch(path: path, method: method, body: body)
        }
    }
    
    // MARK: - Keychain
    
    /// Save a value to the keychain
    /// - Parameters:
    ///   - key: The key to save under
    ///   - value: The value to save
    /// - Returns: True if the save was successful
    @discardableResult
    private func saveToKeychain(key: String, value: String) -> Bool {
        guard let data = value.data(using: .utf8) else {
            return false
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainServiceName,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        
        // First delete any existing item
        SecItemDelete(query as CFDictionary)
        
        // Add the new item
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    /// Load a value from the keychain
    /// - Parameter key: The key to load
    /// - Returns: The value if found, nil otherwise
    private func loadFromKeychain(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainServiceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, 
              let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return value
    }
    
    /// Delete a value from the keychain
    /// - Parameter key: The key to delete
    /// - Returns: True if the delete was successful
    @discardableResult
    private func deleteFromKeychain(key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainServiceName,
            kSecAttrAccount as String: key
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
