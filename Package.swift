// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftEdDSA",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftEdDSA",
            targets: ["SwiftEdDSA"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.15.0"),
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.3.0"),
        .package(url: "https://github.com/leif-ibsen/Digest", from: "1.2.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftEdDSA",
            dependencies: ["BigInt", "ASN1", "Digest"]),
        .testTarget(
            name: "SwiftEdDSATests",
            dependencies: ["SwiftEdDSA"]),
    ]
)
