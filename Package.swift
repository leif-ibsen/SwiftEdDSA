// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftEdDSA",
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "SwiftEdDSA",
            targets: ["SwiftEdDSA"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https;//github.com/leif-ibsen/BigInt", from: "1.14.0"),
        .package(url: "https;//github.com/leif-ibsen/ASN1", from: "2.2.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "SwiftEdDSA",
            dependencies: ["BigInt", "ASN1"]),
        .testTarget(
            name: "SwiftEdDSATests",
            dependencies: ["SwiftEdDSA"]),
    ]
)
