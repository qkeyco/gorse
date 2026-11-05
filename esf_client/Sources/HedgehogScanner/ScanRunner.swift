// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Runs the bundled Rust CLI as a sandbox-inheriting child and decodes its
// JSON report. The child is the only detection code path; this file never
// reads the user's files itself.

import Foundation

enum ScanError: LocalizedError {
    case helperMissing
    case timedOut
    case failed(String)
    case badReport

    var errorDescription: String? {
        switch self {
        case .helperMissing: return "The scanner helper is missing from this app. Reinstall Gorse Scanner."
        case .timedOut: return "The scan took too long and was stopped. Try fewer or smaller folders."
        case .failed(let detail): return detail.isEmpty ? "The scan could not complete." : detail
        case .badReport: return "The scanner returned a report this app could not read."
        }
    }
}

struct ScanEngine: Codable, Hashable {
    let name: String
    let version: String?
    let findings: Int?
    let error: String?
}

struct ScanReport: Codable {
    let findings: [ScanFinding]
    let total: Int
    let files_scanned: Int
    let elapsed_secs: Int
    let interrupted: Bool
    /// Extra engines that ran (TruffleHog, when installed). Absent in older reports.
    let engines: [ScanEngine]?
    /// What the scan did not look at. Optional so a report from an older
    /// helper (which never sent it) still decodes; it is then treated as
    /// unconfirmed, never as complete.
    let coverage: ScanCoverage?
}

struct NamedCount: Codable, Hashable {
    let name: String
    let count: Int
}

struct UnreadableEntry: Codable, Hashable {
    let path: String
    let reason: String
}

/// Mirrors `ScanCoverage` in hedgehog-cli/src/content_scanner.rs.
struct ScanCoverage: Codable, Hashable {
    let complete: Bool
    /// Set by newer scanners: true when something the user would expect to
    /// be checked was not. Absent in older reports, which fall back to
    /// `!complete`.
    let has_gaps: Bool?
    let interrupted: Bool
    let files_scanned: Int
    let files_skipped_by_type: Int
    let skipped_types: [NamedCount]
    let dirs_skipped_by_rule: Int
    let skipped_dirs: [NamedCount]
    let files_unreadable: Int
    let permission_denied: Int
    let other_read_errors: Int
    let unreadable_examples: [UnreadableEntry]
    let files_over_size_limit: Int
    let size_limit_bytes: Int
    let oversize_examples: [String]
    let dirs_beyond_depth_limit: Int
    let files_skipped_other: Int
    let limit_reached: String?
    let images_seen: Int
    let images_content_not_checked: Int
    let image_ocr_cap_reached: Bool
}

extension ScanCoverage {
    /// Sum two coverage reports; a gap in either is a gap in the merge.
    func merging(_ o: ScanCoverage) -> ScanCoverage {
        func sum(_ a: [NamedCount], _ b: [NamedCount]) -> [NamedCount] {
            var counts: [String: Int] = [:]
            for n in a + b { counts[n.name, default: 0] += n.count }
            return counts.map { NamedCount(name: $0.key, count: $0.value) }.sorted { $0.count > $1.count }
        }
        return ScanCoverage(
            complete: complete && o.complete,
            has_gaps: (has_gaps ?? !complete) || (o.has_gaps ?? !o.complete),
            interrupted: interrupted || o.interrupted,
            files_scanned: files_scanned + o.files_scanned,
            files_skipped_by_type: files_skipped_by_type + o.files_skipped_by_type,
            skipped_types: sum(skipped_types, o.skipped_types),
            dirs_skipped_by_rule: dirs_skipped_by_rule + o.dirs_skipped_by_rule,
            skipped_dirs: sum(skipped_dirs, o.skipped_dirs),
            files_unreadable: files_unreadable + o.files_unreadable,
            permission_denied: permission_denied + o.permission_denied,
            other_read_errors: other_read_errors + o.other_read_errors,
            unreadable_examples: Array((unreadable_examples + o.unreadable_examples).prefix(6)),
            files_over_size_limit: files_over_size_limit + o.files_over_size_limit,
            size_limit_bytes: max(size_limit_bytes, o.size_limit_bytes),
            oversize_examples: Array((oversize_examples + o.oversize_examples).prefix(6)),
            dirs_beyond_depth_limit: dirs_beyond_depth_limit + o.dirs_beyond_depth_limit,
            files_skipped_other: files_skipped_other + o.files_skipped_other,
            limit_reached: limit_reached ?? o.limit_reached,
            images_seen: images_seen + o.images_seen,
            images_content_not_checked: images_content_not_checked + o.images_content_not_checked,
            image_ocr_cap_reached: image_ocr_cap_reached || o.image_ocr_cap_reached
        )
    }
}

/// What the results pane should say about how much of the chosen folders
/// was actually checked.
enum CoverageState: Equatable {
    /// Every file was read and checked. The only state that may show green.
    case allClear(filesChecked: Int)
    /// Some files or folders were not checked, for the listed reasons.
    case gaps(headline: String, reasons: [String])
}

extension ScanReport {
    var coverageState: CoverageState {
        guard let coverage else {
            return .gaps(headline: "\(Self.files(files_scanned)) checked. The scanner did not say what it skipped.",
                         reasons: ["This report came from an older scanner helper that does not describe its coverage. Reinstall Gorse Scanner to get a full report."])
        }
        let gaps = coverage.has_gaps ?? !coverage.complete
        if !gaps && !coverage.interrupted && !interrupted {
            return .allClear(filesChecked: coverage.files_scanned)
        }
        return .gaps(headline: Self.headline(for: coverage), reasons: Self.reasons(for: coverage, interrupted: interrupted))
    }

    /// Plain-English notes about files the scanner never reads by design
    /// (PDFs, archives, pictures). Shown under a green result; not gaps.
    var coverageNotes: [String] {
        guard let c = coverage else { return [] }
        var notes: [String] = []
        if c.files_skipped_by_type > 0 {
            notes.append("\(Self.items(c.files_skipped_by_type, "file", "files")) of a type this scanner cannot read, such as PDFs or archives, \(c.files_skipped_by_type == 1 ? "was" : "were") checked by name only.")
        }
        if c.images_content_not_checked > 0 {
            notes.append("\(Self.items(c.images_content_not_checked, "picture was", "pictures were")) checked by file name only. This version does not read text inside pictures.")
        }
        return notes
    }

    private static func files(_ n: Int) -> String { n == 1 ? "1 file was" : "\(n) files were" }

    private static func items(_ n: Int, _ singular: String, _ plural: String) -> String {
        n == 1 ? "1 \(singular)" : "\(n) \(plural)"
    }

    private static func headline(for coverage: ScanCoverage) -> String {
        let notChecked = coverage.files_skipped_by_type
            + coverage.files_unreadable
            + coverage.files_over_size_limit
            + coverage.files_skipped_other
            + coverage.images_content_not_checked
        if notChecked > 0 {
            return "\(files(coverage.files_scanned)) checked. \(files(notChecked)) not checked."
        }
        if coverage.dirs_skipped_by_rule > 0 || coverage.dirs_beyond_depth_limit > 0 {
            return "\(files(coverage.files_scanned)) checked, but some folders were skipped."
        }
        return "\(files(coverage.files_scanned)) checked, but the scan did not finish."
    }

    private static func reasons(for c: ScanCoverage, interrupted: Bool) -> [String] {
        var reasons: [String] = []
        func names(_ list: [NamedCount]) -> String {
            list.isEmpty ? "" : " (" + list.map { $0.count > 1 ? "\($0.name) ×\($0.count)" : $0.name }.joined(separator: ", ") + ")"
        }
        func fileNames(_ paths: [String]) -> String {
            let shown = paths.prefix(3).map { ($0 as NSString).lastPathComponent }
            return shown.isEmpty ? "" : ": " + shown.joined(separator: ", ")
        }
        if c.permission_denied > 0 {
            let examples = c.unreadable_examples.filter { $0.reason == "permission denied" }.map(\.path)
            reasons.append("\(items(c.permission_denied, "file", "files")) could not be read because macOS denied access\(fileNames(examples)).")
        }
        if c.other_read_errors > 0 {
            let examples = c.unreadable_examples.filter { $0.reason != "permission denied" }.map(\.path)
            reasons.append("\(items(c.other_read_errors, "file or folder", "files or folders")) could not be read\(fileNames(examples)).")
        }
        if c.files_over_size_limit > 0 {
            let mb = max(1, c.size_limit_bytes / 1_048_576)
            reasons.append("\(items(c.files_over_size_limit, "file is", "files are")) larger than the \(mb) MB limit and \(c.files_over_size_limit == 1 ? "was" : "were") not read\(fileNames(c.oversize_examples)).")
        }
        if c.files_skipped_by_type > 0 {
            reasons.append("\(items(c.files_skipped_by_type, "file is", "files are")) of a type this scanner cannot read, such as PDFs, archives or app data\(names(c.skipped_types)).")
        }
        if c.images_content_not_checked > 0 {
            reasons.append("\(items(c.images_content_not_checked, "image was", "images were")) checked by file name only. This version does not read text inside pictures.")
        }
        if c.image_ocr_cap_reached {
            reasons.append("The limit on how many pictures can be read in one scan was reached.")
        }
        if c.dirs_skipped_by_rule > 0 {
            reasons.append("\(items(c.dirs_skipped_by_rule, "folder was", "folders were")) skipped because \(c.dirs_skipped_by_rule == 1 ? "it holds" : "they hold") app or developer files\(names(c.skipped_dirs)). Files inside are not counted.")
        }
        if c.dirs_beyond_depth_limit > 0 {
            reasons.append("\(items(c.dirs_beyond_depth_limit, "folder is", "folders are")) nested too deeply and \(c.dirs_beyond_depth_limit == 1 ? "was" : "were") not opened.")
        }
        if c.files_skipped_other > 0 {
            reasons.append("\(items(c.files_skipped_other, "item was", "items were")) skipped because \(c.files_skipped_other == 1 ? "it is" : "they are") not an ordinary file.")
        }
        if let limit = c.limit_reached {
            reasons.append("The scan stopped early: \(limit).")
        }
        if c.interrupted || interrupted {
            reasons.append("The scan stopped before it finished.")
        }
        if reasons.isEmpty {
            reasons.append("The scanner reported that it did not check everything, without saying why.")
        }
        return reasons
    }
}

struct ScanFinding: Codable, Identifiable, Hashable {
    let path: String
    let category: String
    let severity: String
    let confidence: String
    let line: Int
    let preview: String
    let description: String
    let rotation_guide: String?
    let engine: String?

    var id: String { "\(path):\(line):\(category):\(preview)" }
}

enum ScanRunner {
    /// Longest a single scan may run before it is stopped.
    static let timeout: TimeInterval = 900
    /// Largest JSON report accepted from the child.
    static let outputLimit = 16 * 1024 * 1024

    static func helperURL() throws -> URL {
        guard Bundle.main.bundleURL.pathExtension == "app",
              let executable = Bundle.main.executableURL else { throw ScanError.helperMissing }
        let candidate = executable.deletingLastPathComponent().appendingPathComponent("gorse-cli")
        let values = try? candidate.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values?.isRegularFile == true, values?.isSymbolicLink != true,
              FileManager.default.isExecutableFile(atPath: candidate.path) else { throw ScanError.helperMissing }
        return candidate
    }

    /// Scans the given folders. The caller must already hold security-scoped
    /// access to each one; the child inherits that access. With no folders the
    /// CLI uses its own defaults (Desktop, Documents, Downloads, Pictures,
    /// text inside images, Apple Notes), or the whole home folder when
    /// `wholeHome` is set; only the unsandboxed build may ask for that.
    static func scan(folders: [URL], wholeHome: Bool = false, onProgress: ((ScanProgress) -> Void)? = nil) async throws -> ScanReport {
        let helper = try helperURL()
        var arguments = ["scan", "--deep", "--json"]
        for folder in folders { arguments += ["--path", folder.path] }
        if folders.isEmpty && wholeHome { arguments.append("--all-dirs") }
        if onProgress != nil { arguments.append("--progress") }
        let (stdout, stderr, status) = try await execute(helper, arguments: arguments, timeout: timeout, input: nil, onStderrLine: onProgress.map { handler in
            { line in if let progress = ScanProgress.parse(line) { handler(progress) } }
        })
        switch status {
        case .timedOut: throw ScanError.timedOut
        case .exited(let code) where code != 0:
            let detail = String(decoding: stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            throw ScanError.failed(String(detail.suffix(2000)))
        default: break
        }
        guard let report = try? JSONDecoder().decode(ScanReport.self, from: stdout) else { throw ScanError.badReport }
        return report
    }

    enum Status { case exited(Int32), timedOut }

    /// Lets a cancelled Swift task stop the child it is waiting on, so a
    /// long wait (the browser sign-in) ends when the person clicks Cancel.
    private final class ChildHandle: @unchecked Sendable {
        private let lock = NSLock()
        private var process: Process?
        private var cancelled = false
        func attach(_ process: Process) {
            lock.lock(); defer { lock.unlock() }
            self.process = process
            if cancelled { process.terminate() }
        }
        func cancel() {
            lock.lock(); defer { lock.unlock() }
            cancelled = true
            if let process, process.isRunning { process.terminate() }
        }
    }

    static func execute(_ executable: URL, arguments: [String], timeout: TimeInterval, input: Data? = nil, onStderrLine: ((String) -> Void)? = nil) async throws -> (Data, Data, Status) {
        let handle = ChildHandle()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    do { continuation.resume(returning: try executeBlocking(executable, arguments: arguments, timeout: timeout, input: input, onStderrLine: onStderrLine, handle: handle)) }
                    catch { continuation.resume(throwing: error) }
                }
            }
        } onCancel: {
            handle.cancel()
        }
    }

    private static func executeBlocking(_ executable: URL, arguments: [String], timeout: TimeInterval, input: Data? = nil, onStderrLine: ((String) -> Void)? = nil, handle: ChildHandle? = nil) throws -> (Data, Data, Status) {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        let stdinPipe: Pipe? = input == nil ? nil : Pipe()
        process.standardInput = stdinPipe ?? FileHandle.nullDevice
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        let group = DispatchGroup()
        var outData = Data()
        var errData = Data()
        var overflow = false
        let lock = NSLock()
        func drain(_ handle: FileHandle, into store: @escaping (Data) -> Void) {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                while true {
                    let chunk = handle.availableData
                    if chunk.isEmpty { break }
                    store(chunk)
                }
                group.leave()
            }
        }
        drain(stdout.fileHandleForReading) { chunk in
            lock.lock(); defer { lock.unlock() }
            if outData.count + chunk.count > outputLimit { overflow = true } else { outData.append(chunk) }
        }
        var pending = Data()
        drain(stderr.fileHandleForReading) { chunk in
            lock.lock(); defer { lock.unlock() }
            if let onStderrLine {
                // Progress lines are consumed as they arrive; whatever is
                // not a JSON line is kept as ordinary stderr for errors.
                pending.append(chunk)
                while let newline = pending.firstIndex(of: 0x0A) {
                    let lineData = pending.subdata(in: pending.startIndex..<newline)
                    pending.removeSubrange(pending.startIndex...newline)
                    let line = String(decoding: lineData, as: UTF8.self)
                    if line.hasPrefix("{") { onStderrLine(line) } else if errData.count < 64 * 1024 { errData.append(lineData); errData.append(0x0A) }
                }
            } else if errData.count < 64 * 1024 { errData.append(chunk) }
        }

        try process.run()
        if let stdinPipe, let input {
            // Hand the key over on stdin so it never appears in a process list.
            stdinPipe.fileHandleForWriting.write(input)
            try? stdinPipe.fileHandleForWriting.close()
        }
        // Attached after stdin is written so a cancel cannot close the pipe under the write.
        handle?.attach(process)
        let deadline = DispatchTime.now() + timeout
        var timedOut = false
        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }
        if finished.wait(timeout: deadline) == .timedOut {
            timedOut = true
            process.terminate()
            if finished.wait(timeout: .now() + 5) == .timedOut { kill(process.processIdentifier, SIGKILL); finished.wait() }
        }
        group.wait()
        try? stdout.fileHandleForReading.close()
        try? stderr.fileHandleForReading.close()
        if timedOut { return (Data(), errData, .timedOut) }
        if overflow { throw ScanError.badReport }
        return (outData, errData, .exited(process.terminationStatus))
    }
}

/// One progress line from `gorse scan --deep --json --progress`.
struct ScanProgress: Equatable {
    var filesScanned: Int
    var findings: Int
    var currentDir: String?
    var phase: String?

    static func parse(_ line: String) -> ScanProgress? {
        guard let data = line.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let event = json["event"] as? String else { return nil }
        switch event {
        case "progress":
            return ScanProgress(filesScanned: json["files_scanned"] as? Int ?? 0,
                                findings: json["findings"] as? Int ?? 0,
                                currentDir: json["dir"] as? String, phase: nil)
        case "phase":
            return ScanProgress(filesScanned: -1, findings: -1, currentDir: nil, phase: json["name"] as? String)
        default:
            return nil
        }
    }

    var displayDir: String {
        guard let currentDir else { return "" }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return currentDir.hasPrefix(home + "/") ? "~" + currentDir.dropFirst(home.count) : currentDir
    }
}
