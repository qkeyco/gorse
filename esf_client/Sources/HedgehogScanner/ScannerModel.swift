// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Folder selection, security-scoped bookmarks and scan state.

import AppKit
import Foundation

struct ScanFolder: Identifiable, Hashable {
    let id: String
    let url: URL
    let bookmark: Data

    var displayName: String { url.lastPathComponent.isEmpty ? url.path : url.lastPathComponent }
    var displayPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        // Inside the sandbox the home directory is the container; show the real one.
        let realHome = home.components(separatedBy: "/Library/Containers/").first ?? home
        if url.path.hasPrefix(realHome + "/") { return "~" + url.path.dropFirst(realHome.count) }
        return url.path
    }
}

@MainActor
final class ScannerModel: ObservableObject {
    @Published private(set) var folders: [ScanFolder] = []
    @Published private(set) var isScanning = false
    /// Live counts while a scan runs: files read, findings so far, folder.
    @Published private(set) var progress: ScanProgress?
    /// One report per folder (or one for the default places), so adding a
    /// folder scans only that folder and the list is the merge of all.
    @Published private(set) var reportsByFolder: [String: ScanReport] = [:]
    @Published private(set) var report: ScanReport?
    @Published private(set) var errorMessage: String?
    @Published private(set) var lastScanDate: Date?
    /// Desktop build only: scan the whole home folder instead of the default
    /// places when no folders are chosen.
    @Published var wholeHome = false

    /// The App Store build is sandboxed and can only read folders the user
    /// picked; the desktop build may scan the defaults with no picking.
    static let canScanDefaults: Bool = {
        #if HEDGEHOG_DESKTOP
        return true
        #else
        return false
        #endif
    }()

    private static let bookmarksKey = "scanFolderBookmarks"

    init() {
        restoreFolders()
    }

    // MARK: Folder selection

    func chooseFolders() {
        let panel = NSOpenPanel()
        panel.title = "Choose folders to scan"
        panel.message = "Gorse Scanner reads only the folders you choose here. Nothing leaves your Mac."
        panel.prompt = "Add to Scan"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = true
        panel.canCreateDirectories = false
        panel.directoryURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        guard panel.runModal() == .OK else { return }
        for url in panel.urls { add(url) }
        persistFolders()
    }

    func remove(_ folder: ScanFolder) {
        folders.removeAll { $0.id == folder.id }
        reportsByFolder.removeValue(forKey: folder.id)
        rebuildReport()
        persistFolders()
    }

    func removeAll() {
        folders.removeAll()
        reportsByFolder = [:]
        report = nil
        persistFolders()
    }

    private func add(_ url: URL) {
        let standardized = url.standardizedFileURL
        guard !folders.contains(where: { $0.url == standardized }) else { return }
        guard let bookmark = try? standardized.bookmarkData(options: .withSecurityScope,
                                                            includingResourceValuesForKeys: nil,
                                                            relativeTo: nil) else { return }
        folders.append(ScanFolder(id: standardized.path, url: standardized, bookmark: bookmark))
    }

    private func persistFolders() {
        // Only bookmarks are stored, never scan results.
        UserDefaults.standard.set(folders.map(\.bookmark), forKey: Self.bookmarksKey)
    }

    private func restoreFolders() {
        guard let bookmarks = UserDefaults.standard.array(forKey: Self.bookmarksKey) as? [Data] else { return }
        var restored: [ScanFolder] = []
        for bookmark in bookmarks {
            var stale = false
            guard let url = try? URL(resolvingBookmarkData: bookmark, options: .withSecurityScope,
                                     relativeTo: nil, bookmarkDataIsStale: &stale), !stale else { continue }
            if restored.contains(where: { $0.url == url }) { continue }
            restored.append(ScanFolder(id: url.path, url: url, bookmark: bookmark))
        }
        folders = restored
        if restored.count != bookmarks.count { persistFolders() }
    }

    // MARK: Scanning

    static let defaultsKey = "__default_places__"

    /// Folders chosen but not yet scanned since they were added.
    var pendingFolders: [ScanFolder] { folders.filter { reportsByFolder[$0.id] == nil } }
    var hasResults: Bool { !reportsByFolder.isEmpty }

    /// Scans what is new: folders added since the last scan, or everything
    /// when nothing has been scanned yet. `rescanAll` starts over.
    func runScan(rescanAll: Bool = false) async {
        guard !isScanning, !folders.isEmpty || Self.canScanDefaults else { return }
        isScanning = true
        errorMessage = nil
        progress = nil
        defer { isScanning = false; progress = nil }

        if rescanAll { reportsByFolder = [:] }
        let targets: [ScanFolder?] = folders.isEmpty
            ? (reportsByFolder[Self.defaultsKey] == nil ? [nil] : [])
            : (pendingFolders.isEmpty ? folders.map { Optional($0) } : pendingFolders.map { Optional($0) })
        if targets.isEmpty { return }
        if !folders.isEmpty { reportsByFolder.removeValue(forKey: Self.defaultsKey) }

        for target in targets {
            var opened: [URL] = []
            if let folder = target {
                guard folder.url.startAccessingSecurityScopedResource() else {
                    errorMessage = "macOS no longer allows access to \(folder.displayName). Remove it and choose it again."
                    continue
                }
                opened = [folder.url]
            }
            defer { for url in opened { url.stopAccessingSecurityScopedResource() } }
            do {
                let result = try await ScanRunner.scan(folders: opened, wholeHome: wholeHome) { [weak self] update in
                    Task { @MainActor in self?.progress = update }
                }
                reportsByFolder[target?.id ?? Self.defaultsKey] = result
                lastScanDate = Date()
                rebuildReport()
            } catch {
                errorMessage = error.localizedDescription
                break
            }
        }
    }

    /// The merged view of every folder's report.
    private func rebuildReport() {
        let parts = reportsByFolder.values
        guard !parts.isEmpty else { report = nil; return }
        var findings: [ScanFinding] = []
        var total = 0, files = 0, elapsed = 0
        var interrupted = false
        var merged: ScanCoverage?
        for r in parts {
            findings += r.findings
            total += r.total; files += r.files_scanned; elapsed += r.elapsed_secs
            interrupted = interrupted || r.interrupted
            if let c = r.coverage { merged = merged.map { $0.merging(c) } ?? c }
        }
        let engines = Array(Set(parts.flatMap { $0.engines ?? [] }))
        report = ScanReport(findings: findings, total: total, files_scanned: files, elapsed_secs: elapsed, interrupted: interrupted, engines: engines.isEmpty ? nil : engines, coverage: merged)
    }

    func clearResults() {
        report = nil
        reportsByFolder = [:]
        errorMessage = nil
    }

    func reveal(_ finding: ScanFinding) {
        let url = URL(fileURLWithPath: finding.path)
        guard let folder = folders.first(where: { url.path.hasPrefix($0.url.path + "/") }) else { return }
        _ = folder.url.startAccessingSecurityScopedResource()
        NSWorkspace.shared.activateFileViewerSelecting([url])
        folder.url.stopAccessingSecurityScopedResource()
    }

    #if DEBUG
    /// Development-only smoke test: scans the container's own Documents folder
    /// (always readable inside the sandbox) and writes the report to the given
    /// path inside the container. Compiled out of release builds.
    func runSmokeTest(outputPath: String) async {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        var result: [String: Any] = [:]
        do {
            let report = try await ScanRunner.scan(folders: [documents])
            result["ok"] = true
            result["total"] = report.total
            result["categories"] = Array(Set(report.findings.map(\.category))).sorted()
            result["paths"] = report.findings.map(\.path)
        } catch {
            result["ok"] = false
            result["error"] = error.localizedDescription
        }
        let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        try? data?.write(to: URL(fileURLWithPath: outputPath))
    }
    #endif
}
