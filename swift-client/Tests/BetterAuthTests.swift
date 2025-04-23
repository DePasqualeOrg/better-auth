import XCTest
@testable import BetterAuth

final class BetterAuthTests: XCTestCase {
  func testConfigInitialization() {
    let config = BetterAuthConfig(baseURL: "https://example.com")
    XCTAssertEqual(config.baseURL, "https://example.com")
    XCTAssertEqual(config.basePath, "/api/auth")
    
    let customConfig = BetterAuthConfig(baseURL: "https://example.com", basePath: "/custom/auth")
    XCTAssertEqual(customConfig.baseURL, "https://example.com")
    XCTAssertEqual(customConfig.basePath, "/custom/auth")
  }
  
  // Additional tests would be added here for actual client functionality
  // These would likely use mocking to avoid actual network requests
}
