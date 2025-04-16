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
  
  // Example of testing async client methods using async test
  func testSessionObserver() async throws {
    let config = BetterAuthConfig(baseURL: "https://example.com")
    let client = BetterAuth(config: config)
    
    let expectation = expectation(description: "Session observer called")
    let observerId = await client.addSessionObserver { session in
      // Should be called with initial nil session
      XCTAssertNil(session)
      expectation.fulfill()
    }
    
    // Clean up
    await client.removeSessionObserver(id: observerId)
    
    await fulfillment(of: [expectation], timeout: 1.0)
  }
  
  // Additional tests would be added here for actual client functionality
  // These would likely use mocking to avoid actual network requests
}
