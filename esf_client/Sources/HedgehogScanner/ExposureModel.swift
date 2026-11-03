// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// The exposure check: what the credentials on this Mac could reach if the
// laptop were stolen or an agent on it went rogue. Runs the bundled Rust CLI
// (`gorse exposure --json --html …`) and decodes its report. Only the
// Developer ID build (HEDGEHOG_DESKTOP) uses this: the App Store build is
// sandboxed and cannot read the credential locations the check needs.

import AppKit
import Foundation

// MARK: - Report (mirrors hedgehog-cli/src/exposure/report.rs; unknown keys are ignored)

struct ExposureReport: Codable {
    let schema_version: Int?
    let gorse_version: String?
    /// The key the CLI wrote before the rename; read so an older report still shows its version.
    let hedgehog_version: String?
    var cliVersion: String? { gorse_version ?? hedgehog_version }
    let generated_at: String?
    let verified: Bool?
    let findings: [ExposureFinding]
    let summary: ExposureSummary
    let reachable: [ReachablePath]?
    let notes: [String]?

    #if HEDGEHOG_DESKTOP
    /// True when a known credential location could not be read. Such a
    /// check is never shown as clean: a finding may sit in the unread file.
    let incomplete: Bool?
    /// The locations that could not be read, with the reason (never contents).
    let coverage_failures: [CoverageFailure]?
    /// Where the CLI looked (file stores, keychain, agent settings, …) and
    /// what it could not assess. Absent on an older CLI.
    let sources_assessed: [String]?
    let sources_unavailable: [SourceUnavailable]?
    /// What changed since the last recorded run (`--record`). Decoded
    /// leniently: a missing or malformed value is simply no changes.
    let changes: ExposureChanges?

    /// Earlier findings from a source this run could not assess (an engine
    /// no longer installed, a file it could not interpret). Not resolved:
    /// nobody looked, so they may still be present.
    var unassessed: [ChangeEntry] { changes?.unassessed ?? [] }
    /// The CLI's count (the list may be capped), never less than the list.
    var unassessedCount: Int { max(changes?.counts?.unassessed ?? 0, unassessed.count) }

    /// Incomplete by the CLI's own flag, by any recorded coverage failure or
    /// by earlier findings that could not be reassessed: either way the
    /// empty state must not read as an all-clear.
    var isIncomplete: Bool {
        incomplete == true || !(coverage_failures ?? []).isEmpty
            || unassessedCount > 0 || changes?.engine_coverage_lost == true
    }

    /// Findings with at least one path that lands on a production system.
    /// Counted here rather than read from `summary.critical_indirect_paths`,
    /// which counts only the indirect signing and financial paths, so a
    /// Critical finding with a production target is never shown as zero.
    var findingsReachingProduction: Int {
        findings.filter { ($0.paths ?? []).contains { $0.target_production == true } }.count
    }

    /// How the findings stood up to Verify: confirmed by the provider,
    /// inferred from the file alone, or not checkable. Meaningful once `verified`.
    var confidenceCounts: (confirmed: Int, inferred: Int, unchecked: Int) {
        var counts = (confirmed: 0, inferred: 0, unchecked: 0)
        for finding in findings {
            switch (finding.confidence ?? "").lowercased() {
            case "confirmed": counts.confirmed += 1
            case "inferred": counts.inferred += 1
            default: counts.unchecked += 1
            }
        }
        return counts
    }
    #endif
}

struct ExposureSummary: Codable {
    let credentials: Int
    let by_severity: SeverityCounts?
    let critical_indirect_paths: Int?
    let persistent_access_risks: Int?
    let privileged_credentials: Int?
    let reachable_signing_systems: Int?
    let dangerous_blockchain_authorizations: Int?
    #if HEDGEHOG_DESKTOP
    /// Present once the CLI counts Verify outcomes itself; older CLIs omit it.
    let verification_counts: VerificationCounts?
    #endif
}

struct SeverityCounts: Codable {
    let critical: Int
    let high: Int
    let medium: Int
    let low: Int
}

#if HEDGEHOG_DESKTOP
/// A credential location the CLI knows but could not read.
struct CoverageFailure: Codable, Hashable, Identifiable {
    let location: String
    let reason: String

    var id: String { location + "|" + reason }

    /// The path with the home folder abbreviated; the path is safe to show, contents never are.
    var displayLocation: String { ExposureFinding.abbreviateHome(location) }
}

/// `changes` in a recorded report: only what the app shows is read, and
/// every field is optional and decoded on its own, so a CLI that writes a
/// different shape never makes the whole report unreadable.
struct ExposureChanges: Codable, Hashable {
    struct Counts: Codable, Hashable {
        let unassessed: Int?

        init(from decoder: Decoder) throws {
            let c = try? decoder.container(keyedBy: CodingKeys.self)
            unassessed = (try? c?.decodeIfPresent(Int.self, forKey: .unassessed)) ?? nil
        }
    }

    let unassessed: [ChangeEntry]?
    let counts: Counts?
    let engine_coverage_lost: Bool?

    init(from decoder: Decoder) throws {
        let c = try? decoder.container(keyedBy: CodingKeys.self)
        counts = (try? c?.decodeIfPresent(Counts.self, forKey: .counts)) ?? nil
        engine_coverage_lost = (try? c?.decodeIfPresent(Bool.self, forKey: .engine_coverage_lost)) ?? nil
        // One malformed entry drops that entry, not the list.
        if let c, var list = try? c.nestedUnkeyedContainer(forKey: .unassessed) {
            var entries: [ChangeEntry] = []
            while !list.isAtEnd {
                if let entry = try? list.decode(ChangeEntry.self) {
                    entries.append(entry)
                } else if (try? list.decode(DiscardedValue.self)) == nil {
                    break
                }
            }
            unassessed = entries
        } else {
            unassessed = nil
        }
    }

    private struct DiscardedValue: Decodable {
        init(from decoder: Decoder) throws {}
    }
}

/// One finding in `changes`. For an unassessed finding, `severity` is the
/// severity it had in the earlier run and `reason` says why this run could
/// not reassess it.
struct ChangeEntry: Codable, Hashable, Identifiable {
    let kind: String?
    let name: String?
    let location: String?
    let severity: String?
    let previous_severity: String?
    let reason: String?

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func text(_ key: CodingKeys) -> String? {
            guard let value = (try? c.decodeIfPresent(String.self, forKey: key)) ?? nil else { return nil }
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        kind = text(.kind)
        name = text(.name)
        location = text(.location)
        severity = text(.severity)
        previous_severity = text(.previous_severity)
        reason = text(.reason)
    }

    var id: String { [kind, name, location, severity].map { $0 ?? "" }.joined(separator: "|") }

    /// The severity it had when it was last assessed.
    var lastSeverity: String { (previous_severity ?? severity ?? "unknown").lowercased() }
    var title: String { name ?? kind ?? "Credential" }
    var displayLocation: String? { location.map(ExposureFinding.abbreviateHome) }
}

/// A source (keychain, cloud CLI config, …) the CLI could not assess at all.
struct SourceUnavailable: Codable, Hashable, Identifiable {
    let source: String
    let reason: String

    var id: String { source + "|" + reason }
}

/// How the findings fared with Verify, counted by the CLI. Each field is
/// optional so a report from a CLI that counts differently still decodes.
struct VerificationCounts: Codable, Hashable {
    let identity_confirmed: Int?
    let permission_confirmed: Int?
    let local_config: Int?
    /// Written by CLIs before the levels were split: the tool ran, whatever
    /// it established. Read so an older report still decodes.
    let confirmed: Int?
    let failed: Int?
    let unsupported: Int?
    let not_attempted: Int?

    /// True once the CLI reports the split levels.
    var hasLevels: Bool { identity_confirmed != nil || permission_confirmed != nil || local_config != nil }

    /// Anything a provider check produced at all (not counting not_attempted).
    var attempted: Int {
        (identity_confirmed ?? 0) + (permission_confirmed ?? 0) + (local_config ?? 0)
            + (confirmed ?? 0) + (failed ?? 0) + (unsupported ?? 0)
    }

    /// "2 identity confirmed, 1 permission confirmed, 1 local configuration
    /// only, 0 failed, 0 unsupported", or the older form for an older CLI.
    func line(separator: String) -> String {
        let failed = self.failed ?? 0, unsupported = self.unsupported ?? 0
        if hasLevels || confirmed == nil {
            return [
                "\(identity_confirmed ?? 0) identity confirmed",
                "\(permission_confirmed ?? 0) permission confirmed",
                "\(local_config ?? 0) local configuration only",
                "\(failed) failed",
                "\(unsupported) unsupported",
            ].joined(separator: separator)
        }
        return ["\(confirmed ?? 0) answered", "\(failed) failed", "\(unsupported) unsupported"]
            .joined(separator: separator)
    }
}

/// The outcome of asking a provider about one finding.
struct FindingVerification: Codable, Hashable {
    /// "identity_confirmed", "permission_confirmed", "local_config",
    /// "failed", "unsupported" or "not_attempted" (an older CLI wrote
    /// "confirmed" for any check that ran).
    let status: String?
    let detail: String?

    /// "provider check failed: aws sts get-caller-identity timed out", or
    /// nil when there is nothing to say (no status, or not attempted and no detail).
    var line: String? {
        let status = (status ?? "").lowercased()
        let detail = (detail ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let headline: String
        switch status {
        case "identity_confirmed": headline = "identity confirmed by provider"
        case "permission_confirmed": headline = "permission confirmed by provider"
        case "local_config": headline = "local configuration only, provider not asked"
        case "confirmed": headline = "provider check ran"
        case "failed": headline = "check failed"
        case "unsupported": headline = "not supported yet"
        case "not_attempted": headline = "not checked with the provider"
        case "": return nil
        default: headline = "provider check \(status)"
        }
        if status == "not_attempted", detail.isEmpty { return nil }
        return detail.isEmpty ? headline : headline + ": " + detail
    }

    var isFailed: Bool { (status ?? "").lowercased() == "failed" }

    /// The provider authenticated the credential (identity or permission).
    var isProviderConfirmed: Bool {
        ["identity_confirmed", "permission_confirmed"].contains((status ?? "").lowercased())
    }
}
#endif

struct ExposurePersistence: Codable, Hashable {
    let key: String?
    let label: String?
    let survives_cleanup: Bool?
}

struct ExposurePath: Codable, Hashable {
    let target: String
    let target_kind: String?
    let target_production: Bool?
    let outcome: String?
    let outcome_label: String?
    let hops: Int?
    let assurance: String?
    let description: String?
}

struct ReachablePath: Codable, Hashable {
    let path: String?
    let target: String
    let target_kind: String?
    let target_production: Bool?
    let outcome_label: String?
    let hops: Int?
    let assurance: String?
}

struct ExposureFinding: Codable, Identifiable, Hashable {
    let name: String
    let kind: String?
    let kind_label: String?
    let location: String?
    let identity: String?
    let fingerprint: String?
    let severity: String
    let confidence: String?
    let lifetime: String?
    let expired: Bool?
    let target: String?
    let persistence: ExposurePersistence?
    let paths: [ExposurePath]?
    let reasons: [String]?
    let remediation: [String]?
    let evidence: [String]?
    #if HEDGEHOG_DESKTOP
    /// Which source the finding came from (a file store, the keychain, …).
    let source: String?
    /// What the provider said when Verify asked; absent on an older CLI.
    let verification: FindingVerification?
    #endif

    var id: String { "\(fingerprint ?? "")|\(name)|\(location ?? "")" }

    /// Where the credential is, shown with the home folder abbreviated.
    var displayLocation: String {
        guard let location, !location.isEmpty else { return "" }
        return Self.abbreviateHome(location)
    }

    static func abbreviateHome(_ path: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if path.hasPrefix(home + "/") { return "~" + path.dropFirst(home.count) }
        return path
    }

    var survivesWipe: Bool { persistence?.survives_cleanup == true }

    /// The strongest things this credential opens, worst first.
    var sortedPaths: [ExposurePath] {
        (paths ?? []).sorted { lhs, rhs in
            if (lhs.target_production ?? false) != (rhs.target_production ?? false) { return lhs.target_production ?? false }
            return (lhs.hops ?? 0) < (rhs.hops ?? 0)
        }
    }
}

enum SeverityOrder {
    static let order = ["critical", "high", "medium", "low"]
    static func rank(_ s: String) -> Int { order.firstIndex(of: s.lowercased()) ?? order.count }
}

// MARK: - Runner

enum ExposureError: LocalizedError {
    case helperMissing
    case timedOut
    case failed(String)
    case badReport
    #if HEDGEHOG_DESKTOP
    /// Verify was asked for without a Pro or Team licence; carries the CLI's own message.
    case requiresPro(String)
    #endif

    var errorDescription: String? {
        switch self {
        case .helperMissing: return "The checker is missing from this app. Reinstall Gorse."
        case .timedOut: return "The check took too long and was stopped."
        case .failed(let detail): return detail.isEmpty ? "The check could not complete." : detail
        case .badReport: return "The checker returned a report this app could not read."
        #if HEDGEHOG_DESKTOP
        case .requiresPro(let message): return message
        #endif
        }
    }
}

enum ExposureRunner {
    /// Longest a check may run.
    static let timeout: TimeInterval = 300

    /// Where the HTML report of the latest run is kept until the user saves it.
    static func reportURL() throws -> URL {
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                               appropriateFor: nil, create: true)
        let dir = base.appendingPathComponent("Gorse", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        return dir.appendingPathComponent("exposure.html")
    }

    /// Runs the check. The CLI exits 1 when it found anything at or above
    /// "high", which is a result, not a failure, and 3 when the check was
    /// incomplete (a location could not be read) with nothing at the
    /// threshold; both come with a report. Only exit 2 is an error.
    /// With `verify` (desktop build only) the CLI also asks the user's own
    /// provider tools read-only questions; on a Free licence it refuses
    /// before asking anything, printing `{"error": …}` and exiting 2.
    static func check(verify: Bool = false) async throws -> (report: ExposureReport, html: URL) {
        let helper = try ScanRunner.helperURL()
        let html = try reportURL()
        var arguments = ["exposure", "--json", "--html", html.path]
        #if HEDGEHOG_DESKTOP
        if verify { arguments.append("--verify") }
        // Record the run so it appears in the schedule history and feeds
        // change detection ("2 new since yesterday").
        arguments.append("--record")
        #endif
        let (stdout, stderr, status) = try await ScanRunner.execute(helper, arguments: arguments, timeout: timeout)
        switch status {
        case .timedOut: throw ExposureError.timedOut
        case .exited(let code) where !reportExitCodes.contains(code):
            #if HEDGEHOG_DESKTOP
            if let message = jsonError(in: stdout) {
                if verify, code == 2, message.contains("Gorse Pro") { throw ExposureError.requiresPro(message) }
                throw ExposureError.failed(message)
            }
            #endif
            let detail = String(decoding: stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            throw ExposureError.failed(String(detail.suffix(2000)))
        default: break
        }
        guard let report = try? JSONDecoder().decode(ExposureReport.self, from: stdout) else { throw ExposureError.badReport }
        return (report, html)
    }

    /// Exit codes that come with a report on stdout: 0 clean, 1 findings at
    /// or above High and, for the desktop check, 3 incomplete with nothing at
    /// the threshold.
    #if HEDGEHOG_DESKTOP
    private static let reportExitCodes: Set<Int32> = [0, 1, 3]
    #else
    private static let reportExitCodes: Set<Int32> = [0, 1]
    #endif

    #if HEDGEHOG_DESKTOP
    /// The `{"error": "…"}` the CLI prints on stdout in `--json` mode when it refuses to run.
    private static func jsonError(in data: Data) -> String? {
        guard !data.isEmpty,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let error = json["error"] as? String, !error.isEmpty else { return nil }
        return error
    }
    #endif
}

// MARK: - Model

@MainActor
final class ExposureModel: ObservableObject {
    @Published private(set) var isRunning = false
    @Published private(set) var report: ExposureReport?
    @Published private(set) var reportHTML: URL?
    @Published private(set) var errorMessage: String?
    @Published private(set) var lastRunDate: Date?
    #if HEDGEHOG_DESKTOP
    /// True while (and after) a run that asked the providers, so the view can
    /// say "Verifying…" instead of "Checking…".
    @Published private(set) var isVerifying = false
    /// The CLI's refusal when Verify is asked for on the Free plan. Kept apart
    /// from `errorMessage` so the previous report stays on screen and the view
    /// can offer the pricing page.
    @Published private(set) var proMessage: String?
    /// The one-time explanation of what Verify does is open.
    @Published var showVerifyExplanation = false

    static let verifyExplainedKey = "exposure.verifyExplained"
    static let verifyExplanation = "Verify asks your own installed provider tools read-only questions (aws, gh, kubectl, vault, gcloud, az, doctl, eth_getCode) and nothing is sent to Gorse. Each finding says what the provider confirmed: the identity, or a specific permission. A check that only reads local configuration confirms nothing, and the rest stay inferred."

    /// The user has read the explanation once; after that the button runs straight away.
    var verifyExplained: Bool { UserDefaults.standard.bool(forKey: Self.verifyExplainedKey) }

    /// "Verify with providers": explain first, then run.
    func verifyTapped() {
        guard !isRunning else { return }
        if verifyExplained {
            Task { await runCheck(verify: true) }
        } else {
            showVerifyExplanation = true
        }
    }

    func confirmVerify() {
        UserDefaults.standard.set(true, forKey: Self.verifyExplainedKey)
        showVerifyExplanation = false
        Task { await runCheck(verify: true) }
    }

    func dismissProMessage() { proMessage = nil }
    #endif

    func runCheck() async { await runCheck(verify: false) }

    private func runCheck(verify: Bool) async {
        guard !isRunning else { return }
        isRunning = true
        errorMessage = nil
        #if HEDGEHOG_DESKTOP
        proMessage = nil
        showVerifyExplanation = false
        isVerifying = verify
        #endif
        defer { isRunning = false }
        do {
            let result = try await ExposureRunner.check(verify: verify)
            report = result.report
            reportHTML = FileManager.default.fileExists(atPath: result.html.path) ? result.html : nil
            lastRunDate = Date()
        } catch {
            #if HEDGEHOG_DESKTOP
            if case ExposureError.requiresPro(let message) = error {
                // The free report from before is still valid; only Verify was refused.
                proMessage = message
                isVerifying = false
                return
            }
            #endif
            report = nil
            reportHTML = nil
            errorMessage = error.localizedDescription
        }
    }

    /// Findings grouped by severity, worst first.
    var grouped: [(severity: String, findings: [ExposureFinding])] {
        guard let report else { return [] }
        let groups = Dictionary(grouping: report.findings) { $0.severity.lowercased() }
        return groups.keys.sorted { SeverityOrder.rank($0) < SeverityOrder.rank($1) }
            .map { key in (key, groups[key]!.sorted { ($0.kind_label ?? $0.name) < ($1.kind_label ?? $1.name) }) }
    }

    func saveReport() {
        guard let reportHTML else { return }
        let panel = NSSavePanel()
        panel.title = "Save the exposure report"
        panel.nameFieldStringValue = "gorse-exposure.html"
        panel.canCreateDirectories = true
        panel.directoryURL = FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        do {
            if FileManager.default.fileExists(atPath: destination.path) { try FileManager.default.removeItem(at: destination) }
            try FileManager.default.copyItem(at: reportHTML, to: destination)
        } catch {
            errorMessage = "The report could not be saved: \(error.localizedDescription)"
        }
    }

    func openReport() {
        guard let reportHTML else { return }
        NSWorkspace.shared.open(reportHTML)
    }

    /// Tells the checker that a target is a production system (written to
    /// the infrastructure map by the CLI) and runs the check again.
    func markProduction(_ target: String) async {
        guard !isRunning else { return }
        do {
            let helper = try ScanRunner.helperURL()
            let (stdout, stderr, status) = try await ScanRunner.execute(helper, arguments: ["exposure", "--mark-production", target, "--json"], timeout: 30)
            if case .exited(let code) = status, code != 0 {
                let detail = String(decoding: stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                errorMessage = detail.isEmpty ? "Could not mark \(target) as production." : String(detail.suffix(400))
                return
            }
            if let json = try? JSONSerialization.jsonObject(with: stdout) as? [String: Any], let error = json["error"] as? String {
                errorMessage = error
                return
            }
        } catch {
            errorMessage = error.localizedDescription
            return
        }
        await runCheck()
    }

    func reveal(_ finding: ExposureFinding) {
        guard let location = finding.location, !location.isEmpty else { return }
        let url = URL(fileURLWithPath: location)
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
}
