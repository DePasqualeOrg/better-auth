import Foundation

/**
 * Configuration for Better Auth client
 */
public struct BetterAuthConfig {
    /// Base URL for the Better Auth server
    public let baseURL: String
    
    /// Base path for the API endpoints (defaults to "/api/auth")
    public let basePath: String?
    
    /// Initialize with configuration
    /// - Parameters:
    ///   - baseURL: Base URL for the Better Auth server
    ///   - basePath: Base path for the API endpoints (defaults to "/api/auth")
    public init(baseURL: String, basePath: String? = "/api/auth") {
        self.baseURL = baseURL
        self.basePath = basePath
    }
}