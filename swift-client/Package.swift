// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "BetterAuth",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "BetterAuth",
            targets: ["BetterAuth"]),
        .library(
            name: "BetterAuthExamples",
            targets: ["BetterAuthExamples"]),
    ],
    dependencies: [
        // No external dependencies
    ],
    targets: [
        .target(
            name: "BetterAuth",
            dependencies: []),
        .target(
            name: "BetterAuthExamples",
            dependencies: ["BetterAuth"]),
        .testTarget(
            name: "BetterAuthTests",
            dependencies: ["BetterAuth"],
            path: "Tests"),
    ]
)
