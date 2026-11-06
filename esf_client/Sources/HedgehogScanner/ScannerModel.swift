// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Folder selection, security-scoped bookmarks and scan state.

import AppKit
import CryptoKit
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

/// A place the default Deep Scan reads, as `gorse scan --list-places` names it.
struct ScanPlace: Decodable, Identifiable, Hashable {
    let kind: String
    let label: String
    let path: String?
    let detail: String
    var id: String { kind + "|" + label + "|" + (path ?? "") }
    var displayPath: String? {
        guard let path else { return nil }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if path == home { return "~" }
        return path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
    }
    var symbol: String {
        switch kind {
        case "settings": return "gearshape"
        case "code": return "chevron.left.forwardslash.chevron.right"
        case "pictures": return "photo"
        case "notes": return "note.text"
        default: return "folder"
        }
    }
}

private struct ScanPlaceList: Decodable { let places: [ScanPlace] }

@MainActor
final class ScannerModel: ObservableObject {
    /// What a Deep Scan with no folders chosen reads, listed so people can
    /// see it before they start. Empty until loaded (or with an older CLI).
    @Published private(set) var defaultPlaces: [ScanPlace] = []
    @Published private(set) var folders: [ScanFolder] = []
    @Published private(set) var isScanning = false
    /// Live counts while a scan runs: files read, findings so far, folder.
    @Published private(set) var progress: ScanProgress?
    /// Findings from the scan in progress, newest first, shown while it runs.
    @Published private(set) var liveFindings: [ScanFinding] = []
    /// Ids already in `liveFindings`: a resumed scan re-reads a folder it
    /// stopped inside and reports some findings a second time.
    private var liveIDs: Set<String> = []
    /// Set while a Stop asked the scan to finish early with what it has.
    @Published private(set) var isStopping = false
    private var stopper: ScanRunner.ChildHandle?
    /// How much the running scan will read, once the CLI has counted it.
    @Published private(set) var estimate: (files: Int, bytes: Int64)?
    /// Pictures read for text so far, while that step runs.
    @Published private(set) var images: (done: Int, total: Int)?
    /// When the folder-reading part began, for the time-left estimate.
    private var filesStartedAt: (date: Date, files: Int)?
    /// Bumped when resume files change, so the button label refreshes.
    @Published private(set) var resumeRevision = 0
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

    /// Folds one progress line into the live view. A finding keeps the folder
    /// and step shown from the last line, since it names neither; a step
    /// change keeps the counts (its own line carries none).
    private func receive(_ update: ScanProgress) {
        if let done = update.imagesDone, let total = update.imagesTotal {
            images = (done, total)
            var merged = progress ?? update
            merged.phase = "images"
            merged.currentDir = nil
            progress = merged
            return
        }
        if let files = update.filesTotal {
            estimate = (files, update.bytesTotal ?? 0)
            return
        }
        if let finding = update.finding {
            if liveIDs.insert(finding.id).inserted { liveFindings.insert(finding, at: 0) }
            var merged = progress ?? update
            // Notes and pictures findings carry 0 files; never count back.
            merged.filesScanned = max(merged.filesScanned, update.filesScanned)
            merged.findings = max(merged.findings, update.findings)
            merged.finding = nil
            progress = merged
            return
        }
        if let phase = update.phase {
            var merged = progress ?? update
            merged.phase = phase
            merged.currentDir = nil
            progress = merged
            return
        }
        if update.filesScanned >= 0, filesStartedAt == nil {
            filesStartedAt = (Date(), update.filesScanned)
        }
        progress = update
    }

    /// What the scan is doing when it is not walking folders, or nil when
    /// the progress line already says it ("Text in pictures: 75 of 5,000").
    nonisolated static func stepDescription(_ phase: String?, imagesKnown: Bool) -> String? {
        switch phase {
        case nil: return nil
        case "notes": return "Reading Apple Notes…"
        case "images": return imagesKnown ? nil : "Reading the text inside pictures…"
        case "trufflehog": return "Running TruffleHog's detectors…"
        default: return "Finishing…"
        }
    }

    /// Asks the running scan to stop and report what it found so far. The
    /// results then show as an incomplete scan; nothing is thrown away, and
    /// the next scan carries on from where this one stopped.
    func stopScan() {
        guard isScanning, !isStopping else { return }
        isStopping = true
        stopper?.interrupt()
    }

    /// Share of the scan done, once the total is known (never shows 100%
    /// until the scan really ends, since the count is an estimate).
    var fractionDone: Double? {
        if progress?.phase == "images", let images, images.total > 0 {
            return min(Double(images.done) / Double(images.total), 0.99)
        }
        guard let estimate, estimate.files > 0, let p = progress, p.filesScanned >= 0 else { return nil }
        return min(Double(p.filesScanned) / Double(estimate.files), 0.99)
    }

    /// "12,153 of 40,210 files (1.9 GB) · 40 findings · about 25 min left".
    var progressLine: String {
        let findings = liveFindings.tally.summary(empty: "nothing found yet")
        if progress?.phase == "images", let images {
            return "Text in pictures: \(images.done.formatted()) of \(images.total.formatted()) · \(findings)"
        }
        let read = max(progress?.filesScanned ?? 0, 0)
        guard let estimate else { return "\(read.formatted()) files read · \(findings) · counting…" }
        let size = ByteCountFormatter.string(fromByteCount: estimate.bytes, countStyle: .file)
        let left = timeLeft.map { " · \($0)" } ?? ""
        return "\(read.formatted()) of \(estimate.files.formatted()) files (\(size)) · \(findings)\(left)"
    }

    /// Where a stopped scan of `id` keeps its place: owner-only, in the
    /// app's own support folder.
    static func resumeFile(for id: String) -> URL {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let name = SHA256.hash(data: Data(id.utf8)).map { String(format: "%02x", $0) }.joined().prefix(24)
        return support.appendingPathComponent("Gorse/resume/\(name).json")
    }

    /// True when the next scan carries on from a stopped one.
    var canResume: Bool {
        _ = resumeRevision
        let ids = folders.isEmpty ? [Self.defaultsKey] : folders.map(\.id)
        return ids.contains { FileManager.default.fileExists(atPath: Self.resumeFile(for: $0).path) }
    }

    /// "about 25 min left", from the reading speed so far, once there is
    /// enough of it to go on.
    var timeLeft: String? {
        guard let estimate, let start = filesStartedAt, let p = progress, p.phase == nil, p.filesScanned > start.files else { return nil }
        let elapsed = Date().timeIntervalSince(start.date)
        guard elapsed > 10 else { return nil }
        let rate = Double(p.filesScanned - start.files) / elapsed
        let remaining = Double(max(estimate.files - p.filesScanned, 0)) / max(rate, 0.1)
        let f = DateComponentsFormatter()
        f.allowedUnits = remaining >= 3600 ? [.hour, .minute] : [.minute]
        f.unitsStyle = .abbreviated
        return "about \(f.string(from: max(remaining, 60)) ?? "") left"
    }

    /// Share of the disk's used space this scan reads.
    var diskCoverage: Int? {
        guard let estimate,
              let values = try? URL(fileURLWithPath: NSHomeDirectory()).resourceValues(forKeys: [.volumeTotalCapacityKey, .volumeAvailableCapacityForImportantUsageKey]),
              let total = values.volumeTotalCapacity, let free = values.volumeAvailableCapacityForImportantUsage else { return nil }
        let used = Double(Int64(total) - free)
        guard used > 0 else { return nil }
        return max(1, min(100, Int((Double(estimate.bytes) / used * 100).rounded())))
    }

    /// Asks the bundled CLI which places a default Deep Scan reads.
    func loadDefaultPlaces() async {
        guard Self.canScanDefaults, defaultPlaces.isEmpty,
              let helper = try? ScanRunner.helperURL(),
              let (stdout, _, status) = try? await ScanRunner.execute(helper, arguments: ["scan", "--list-places"], timeout: 15),
              case .exited = status,
              let list = try? JSONDecoder().decode(ScanPlaceList.self, from: stdout) else { return }
        defaultPlaces = list.places
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
        // A folder inside one already chosen is read with it; adding it too
        // would read every file in it twice.
        guard !folders.contains(where: { Self.isInside(standardized, $0.url) }) else { return }
        guard let bookmark = try? standardized.bookmarkData(options: .withSecurityScope,
                                                            includingResourceValuesForKeys: nil,
                                                            relativeTo: nil) else { return }
        // Choosing a parent replaces the folders inside it.
        for inner in folders where Self.isInside(inner.url, standardized) { reportsByFolder.removeValue(forKey: inner.id) }
        folders.removeAll { Self.isInside($0.url, standardized) }
        folders.append(ScanFolder(id: standardized.path, url: standardized, bookmark: bookmark))
        rebuildReport()
    }

    /// True when `inner` is strictly inside `outer`.
    static func isInside(_ inner: URL, _ outer: URL) -> Bool {
        let o = outer.standardizedFileURL.path, i = inner.standardizedFileURL.path
        return i.hasPrefix(o.hasSuffix("/") ? o : o + "/")
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
        // Older versions let a folder and one inside it both be chosen.
        let chosen = restored
        restored.removeAll { inner in chosen.contains { Self.isInside(inner.url, $0.url) } }
        folders = restored
        if restored.count != bookmarks.count { persistFolders() }
    }

    // MARK: Scanning

    static let defaultsKey = "__default_places__"

    /// Folders chosen but not yet scanned since they were added.
    /// Folders not scanned yet, or stopped part-way (they have a resume file).
    var pendingFolders: [ScanFolder] {
        folders.filter { reportsByFolder[$0.id] == nil || FileManager.default.fileExists(atPath: Self.resumeFile(for: $0.id).path) }
    }
    var hasResults: Bool { !reportsByFolder.isEmpty }

    /// Scans what is new: folders added since the last scan, or everything
    /// when nothing has been scanned yet. `rescanAll` starts over.
    func runScan(rescanAll: Bool = false) async {
        guard !isScanning, !folders.isEmpty || Self.canScanDefaults else { return }
        isScanning = true
        errorMessage = nil
        progress = nil
        liveFindings = []
        liveIDs = []
        isStopping = false
        estimate = nil
        images = nil
        filesStartedAt = nil
        defer { isScanning = false; isStopping = false; stopper = nil; progress = nil; liveFindings = []; liveIDs = []; estimate = nil; images = nil; filesStartedAt = nil; resumeRevision += 1 }

        if rescanAll {
            reportsByFolder = [:]
            for folder in folders { try? FileManager.default.removeItem(at: Self.resumeFile(for: folder.id)) }
            try? FileManager.default.removeItem(at: Self.resumeFile(for: Self.defaultsKey))
        }
        // The default places are always scanned when asked: a first scan, a
        // Rescan, or a Resume (the resume file makes it carry on, not restart).
        let targets: [ScanFolder?] = folders.isEmpty
            ? [nil]
            : (pendingFolders.isEmpty ? folders.map { Optional($0) } : pendingFolders.map { Optional($0) })
        if targets.isEmpty { return }
        if !folders.isEmpty { reportsByFolder.removeValue(forKey: Self.defaultsKey) }

        for target in targets {
            if isStopping { break }
            // Counts, totals and speed belong to one run of the helper; the
            // findings list carries on across the folders.
            progress = nil
            estimate = nil
            images = nil
            filesStartedAt = nil
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
                let handle = ScanRunner.ChildHandle()
                stopper = handle
                // Whole-home scans are not resumed: the Pro check runs each time.
                let resume = wholeHome && target == nil ? nil : Self.resumeFile(for: target?.id ?? Self.defaultsKey)
                let result = try await ScanRunner.scan(folders: opened, wholeHome: wholeHome, stopper: handle, resumeFile: resume) { [weak self] update in
                    Task { @MainActor in self?.receive(update) }
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
        if finding.isAppleNote {
            // A note has no file to show; open Notes instead.
            if let notes = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Notes") {
                NSWorkspace.shared.openApplication(at: notes, configuration: NSWorkspace.OpenConfiguration())
            }
            return
        }
        let url = URL(fileURLWithPath: finding.path)
        guard let folder = folders.first(where: { url.path.hasPrefix($0.url.path + "/") }) else {
            // The desktop build is not sandboxed, so files from the default
            // places can be shown without a folder grant.
            if Self.canScanDefaults { NSWorkspace.shared.activateFileViewerSelecting([url]) }
            return
        }
        _ = folder.url.startAccessingSecurityScopedResource()
        NSWorkspace.shared.activateFileViewerSelecting([url])
        folder.url.stopAccessingSecurityScopedResource()
    }

    /// System Settings, Privacy & Security, Full Disk Access.
    nonisolated static let fullDiskAccessSettings = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!

    func openFullDiskAccessSettings() {
        NSWorkspace.shared.open(Self.fullDiskAccessSettings)
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
