// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "PassportScanner",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "MRTDKit", targets: ["MRTDKit"]),
        .executable(name: "PassportScanner", targets: ["PassportScanner"]),
        .executable(name: "mrtd-read", targets: ["mrtd-read"]),
    ],
    targets: [
        .target(name: "MRTDKit"),
        .executableTarget(name: "PassportScanner", dependencies: ["MRTDKit"]),
        .executableTarget(name: "mrtd-read", dependencies: ["MRTDKit"]),
        .testTarget(name: "MRTDKitTests", dependencies: ["MRTDKit"]),
    ]
)
