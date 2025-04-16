// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "BetterAuth",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "BetterAuth",
            targets: ["BetterAuth"]),
    ],
    dependencies: [
        // No external dependencies
    ],
    targets: [
        .target(
            name: "BetterAuth",
            dependencies: [],
            path: ".",
            sources: [
                "BetterAuth.swift", 
                "BetterAuthConfig.swift", 
                "Models.swift", 
                "Errors.swift",
                "Examples.swift"
            ]),
        .testTarget(
            name: "BetterAuthTests",
            dependencies: ["BetterAuth"],
            path: "Tests"),
    ]
)