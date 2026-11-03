// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// On first launch from somewhere like Downloads, offer to move the app into
// the Applications folder and relaunch from there. A zip cannot install
// itself, so this is the "double-click and it is installed" step. Desktop
// build only: the App Store build is already in Applications.

#if HEDGEHOG_DESKTOP
import AppKit
import Foundation

enum MoveToApplications {
    private static let declinedKey = "moveToApplicationsDeclined"

    /// True when the running bundle is already inside an Applications folder
    /// (system-wide or the user's own).
    static var isInstalled: Bool {
        let path = Bundle.main.bundleURL.standardizedFileURL.path
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return path.hasPrefix("/Applications/") || path.hasPrefix(home + "/Applications/")
    }

    /// Ask once per launch location. If the user agrees, copy the bundle into
    /// Applications, open the copy and quit this one.
    @MainActor
    static func offerIfNeeded() {
        guard !isInstalled, Bundle.main.bundleURL.pathExtension == "app" else { return }
        let defaults = UserDefaults.standard
        if defaults.bool(forKey: declinedKey) { return }

        let alert = NSAlert()
        alert.messageText = "Move Gorse to your Applications folder?"
        alert.informativeText = "Gorse is running from \(Bundle.main.bundleURL.deletingLastPathComponent().lastPathComponent). Moving it to Applications keeps it with your other apps and lets you delete the download."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Move to Applications")
        alert.addButton(withTitle: "Not Now")
        alert.showsSuppressionButton = true
        alert.suppressionButton?.title = "Don't ask again"
        let response = alert.runModal()
        if alert.suppressionButton?.state == .on { defaults.set(true, forKey: declinedKey) }
        guard response == .alertFirstButtonReturn else { return }

        do {
            let destination = try move()
            relaunch(from: destination)
        } catch {
            let failure = NSAlert()
            failure.messageText = "Gorse could not be moved"
            failure.informativeText = "\(error.localizedDescription)\n\nDrag Gorse from \(Bundle.main.bundleURL.deletingLastPathComponent().lastPathComponent) into your Applications folder instead."
            failure.runModal()
        }
    }

    private static func move() throws -> URL {
        let fm = FileManager.default
        let source = Bundle.main.bundleURL.standardizedFileURL
        let name = source.lastPathComponent
        // System Applications when writable, otherwise the user's own folder.
        var folder = URL(fileURLWithPath: "/Applications", isDirectory: true)
        if !fm.isWritableFile(atPath: folder.path) {
            folder = fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications", isDirectory: true)
            try fm.createDirectory(at: folder, withIntermediateDirectories: true)
        }
        let destination = folder.appendingPathComponent(name)
        if fm.fileExists(atPath: destination.path) {
            // Replace an older copy; a running one would be busy, so trash it.
            try fm.trashItem(at: destination, resultingItemURL: nil)
        }
        try fm.copyItem(at: source, to: destination)
        // The copy carries the same signature and staple; remove the download
        // so two copies do not confuse Launch Services. Failure is harmless.
        try? fm.trashItem(at: source, resultingItemURL: nil)
        return destination
    }

    private static func relaunch(from destination: URL) {
        let config = NSWorkspace.OpenConfiguration()
        config.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: destination, configuration: config) { _, _ in
            DispatchQueue.main.async { NSApplication.shared.terminate(nil) }
        }
    }
}
#endif
