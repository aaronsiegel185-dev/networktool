// swift-tools-version:5.9
import PackageDescription

// Everything the app knows how to do lives here rather than in the app target,
// so it can be unit-tested without a simulator and reused by a future macOS or
// watch target without being untangled first.
let package = Package(
    name: "NettoolKit",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "NettoolKit", targets: ["NettoolKit"])
    ],
    targets: [
        .target(name: "NettoolKit"),
        // No resource bundle: the test captures are assembled byte by byte in
        // Fixture, so what each field means is visible beside the assertion
        // that depends on it rather than buried in a binary blob.
        .testTarget(name: "NettoolKitTests", dependencies: ["NettoolKit"])
    ]
)
