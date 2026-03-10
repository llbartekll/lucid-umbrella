// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "Erc7730",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .library(name: "Erc7730", targets: ["Erc7730"])
    ],
    targets: [
        .binaryTarget(
            name: "Erc7730Rust",
            path: "target/ios/liberc7730.xcframework"
        ),
        .target(
            name: "Erc7730",
            dependencies: ["Erc7730Rust"],
            path: "bindings/swift",
            exclude: ["erc7730FFI.h", "erc7730FFI.modulemap"],
            publicHeadersPath: "."
        )
    ]
)
