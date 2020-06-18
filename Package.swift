// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftEdDSA",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "SwiftEdDSA",
            targets: ["SwiftEdDSA"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "1.2.1"),
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.1.2"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "SwiftEdDSA",
            dependencies: ["ASN1", "BigInt"]),
        .testTarget(
            name: "SwiftEdDSATests",
            dependencies: ["SwiftEdDSA"]),
    ]
)
