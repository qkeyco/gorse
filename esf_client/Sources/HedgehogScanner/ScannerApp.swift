// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Gorse Scanner — the App Store product.
//
// A sandboxed, windowed app that scans only the folders the user chooses for
// exposed secrets and sensitive content. It has no system extension, no
// network filter, no agent hooks and no network access. All detection runs in
// the bundled Rust CLI, launched as a child that inherits this app's sandbox
// and therefore only the folder access the user granted through the open panel.

import SwiftUI

#if HEDGEHOG_DESKTOP
// Gorse.app, the Developer ID download: the exposure check first, the
// folder scan second. Not sandboxed, because the check must read the
// credential locations in the home folder; it still reads only, prints no
// secret and has no network use of its own.
@main
struct HedgehogDesktopApp: App {
    @StateObject private var exposure = ExposureModel()
    @StateObject private var scanner = ScannerModel()
    @StateObject private var license = LicenseModel()
    @StateObject private var update = UpdateModel()
    @StateObject private var engines = EngineModel()
    @StateObject private var schedule = ScheduleModel()
    @State private var tab: DesktopTab = .exposure

    enum DesktopTab: Hashable { case exposure, folders }

    static let version: String = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"

    var body: some Scene {
        WindowGroup("Gorse \(HedgehogDesktopApp.version)") {
            VStack(spacing: 0) {
            UpdateBanner(model: update)
            TabView(selection: $tab) {
                ExposureView(model: exposure)
                    .tabItem { Label("Fast Scan", systemImage: "key.viewfinder") }
                    .tag(DesktopTab.exposure)
                ScannerView(model: scanner)
                    .tabItem { Label("Deep Scan", systemImage: "doc.text.magnifyingglass") }
                    .tag(DesktopTab.folders)
            }
            }
            .frame(minWidth: 820, minHeight: 620)
            .environmentObject(license)
            .environmentObject(engines)
            .environmentObject(schedule)
            .toolbar {
                ToolbarItem(placement: .primaryAction) { LicenseBadge(model: license) }
            }
            .task {
                #if DEBUG
                // Development only: GORSE_SHOT=<file.png> [GORSE_SHOT_TAB=deep]
                // draws the window into a PNG and quits, so a change can be
                // looked at without screen-recording permission.
                if let shot = ProcessInfo.processInfo.environment["GORSE_SHOT"] {
                    if ProcessInfo.processInfo.environment["GORSE_SHOT_TAB"] == "deep" { tab = .folders }
                    await license.refresh()
                    try? await Task.sleep(nanoseconds: 6_000_000_000)
                    DevShot.write(to: shot)
                    NSApp.terminate(nil)
                    return
                }
                #endif
                // A zip cannot install itself: offer the move before anything
                // else, so the relaunch happens from Applications.
                MoveToApplications.offerIfNeeded()
                await license.refresh()
                await update.check()
                await engines.refresh()
                await schedule.refresh()
                // The question the app exists to answer; ask it as soon as the
                // window is up rather than waiting for a click.
                if exposure.report == nil && !exposure.isRunning { await exposure.runCheck() }
            }
            .onChange(of: exposure.isRunning) { running in
                // Every manual run is recorded by the CLI; re-read the
                // schedule status so "Last check" and the history follow.
                if !running { Task { await schedule.refresh() } }
            }
        }
        .windowResizability(.contentSize)
        .defaultSize(width: 920, height: 720)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Check") {
                Button("Run Fast Scan") { Task { await exposure.runCheck() } }
                    .keyboardShortcut("r")
                    .disabled(exposure.isRunning)
                Button("Save Report…") { exposure.saveReport() }
                    .keyboardShortcut("s")
                    .disabled(exposure.reportHTML == nil)
                Divider()
                Button("Upgrade to Pro…") { license.openPricing() }
                Divider()
                Button("Choose Folders to Scan…") { scanner.chooseFolders() }
                    .keyboardShortcut("o")
                Button("Run Deep Scan") { Task { await scanner.runScan() } }
                    .disabled(scanner.isScanning)
            }
        }
    }
}
#else
@main
struct HedgehogScannerApp: App {
    @StateObject private var model = ScannerModel()

    var body: some Scene {
        WindowGroup("Gorse Scanner") {
            ScannerView(model: model)
                .frame(minWidth: 760, minHeight: 520)
        }
        .windowResizability(.contentSize)
        .defaultSize(width: 860, height: 600)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Scan") {
                Button("Choose Folders…") { model.chooseFolders() }
                    .keyboardShortcut("o")
                Button("Run Scan") { Task { await model.runScan() } }
                    .keyboardShortcut("r")
                    .disabled(model.folders.isEmpty || model.isScanning)
            }
        }
    }
}
#endif

#if DEBUG && HEDGEHOG_DESKTOP
import AppKit

/// Development only: renders the front window's content into a PNG.
enum DevShot {
    @MainActor static func write(to path: String) {
        guard let view = NSApp.windows.first(where: { $0.isVisible })?.contentView?.superview else { return }
        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
    }
}
#endif
