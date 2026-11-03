// swift-tools-version: 5.9
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//
// The public package builds the Gorse Mac app (bundle-desktop.sh, built with
// -Xswiftc -DHEDGEHOG_DESKTOP) and the sandboxed App Store Scanner
// (bundle-scanner.sh) from the same HedgehogScanner target. Both run the
// bundled `gorse` command-line tool for every check.
import PackageDescription

let package = Package(
    name: "Gorse",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "HedgehogScanner", targets: ["HedgehogScanner"]),
        .library(name: "HedgehogLicensing", targets: ["HedgehogLicensing"]),
    ],
    targets: [
        // Licence lease verification and the machine identifier.
        .target(
            name: "HedgehogLicensing",
            path: "Sources/Shared",
            sources: ["MachineID.swift", "LicenseManager.swift"]
        ),
        // The window app: the exposure check and the folder scan.
        .executableTarget(
            name: "HedgehogScanner",
            dependencies: [],
            path: "Sources/HedgehogScanner",
            exclude: ["Resources/Info.plist", "Resources/Info-Desktop.plist"]
        ),
        // How the app turns the CLI's JSON report into its result states.
        .testTarget(
            name: "HedgehogScannerTests",
            dependencies: ["HedgehogScanner"],
            path: "Tests/HedgehogScannerTests"
        ),
    ]
)
