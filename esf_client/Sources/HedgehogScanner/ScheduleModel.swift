// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Scheduled checks: Gorse re-runs the exposure check on its own (a launch
// agent the CLI installs) and keeps a history of runs so the app can say
// what changed since last time. The CLI owns the schedule, the licence gate
// and the history file; this asks `gorse-cli schedule …` and shows the
// answer. Desktop build only: the sandboxed App Store Scanner cannot write
// ~/Library/LaunchAgents.

#if HEDGEHOG_DESKTOP
import AppKit
import Foundation
import SwiftUI

// MARK: - CLI shapes (every field optional so an older or newer CLI still decodes)

struct ScheduleCounts: Codable, Hashable {
    let critical: Int?
    let high: Int?
    let medium: Int?
    let low: Int?

    var total: Int { (critical ?? 0) + (high ?? 0) + (medium ?? 0) + (low ?? 0) }
}

struct ScheduleRun: Codable, Hashable, Identifiable {
    let at: String?
    let ok: Bool?
    let trigger: String?
    let counts: ScheduleCounts?
    let new: Int?
    let worsened: Int?
    let resolved: Int?
    /// Earlier findings this run could not reassess (their source was not
    /// assessed). Never resolved. Absent on an older CLI.
    let unassessed: Int?
    let incomplete: Bool?
    let coverage_failures: Int?
    let engine_coverage_lost: Bool?
    /// The full change list, when a CLI includes it; decoded leniently.
    let changes: ExposureChanges?
    let message: String?

    /// The unassessed count from whichever field the CLI wrote.
    var unassessedCount: Int {
        max(unassessed ?? 0, changes?.counts?.unassessed ?? 0, changes?.unassessed?.count ?? 0)
    }

    var id: String { "\(at ?? "")|\(trigger ?? "")|\(ok.map(String.init) ?? "")" }
    var date: Date? { ScheduleDates.parse(at) }

    /// What the run established. Incomplete wins over everything: a run
    /// that could not read some locations never reads as a clean result,
    /// whatever `ok` or the counts say. `gorse schedule history --json`
    /// omits `ok` and carries `incomplete` instead, so a missing `ok` is
    /// unknown, and only an explicit `ok: true` or `incomplete: false`
    /// lets a run with no findings say "no findings".
    var outcome: ScheduleRunOutcome {
        if incomplete == true {
            return .incomplete(notRead: coverage_failures ?? 0, notAssessed: unassessedCount)
        }
        if ok == false { return .failed }
        let total = counts?.total ?? 0
        if total > 0 { return .findings(total) }
        if ok == true || incomplete == false { return .clean }
        return .unknown
    }

    /// "incomplete: 1 location not read · 2 not assessed", or nil when the
    /// run was not incomplete.
    var incompleteSummary: String? {
        guard case let .incomplete(notRead, notAssessed) = outcome else { return nil }
        var text = "incomplete: \(notRead) location\(notRead == 1 ? "" : "s") not read"
        if notAssessed > 0 { text += " · \(notAssessed) not assessed" }
        return text
    }
}

enum ScheduleRunOutcome: Equatable {
    /// Some locations were not read (and maybe some findings not reassessed).
    case incomplete(notRead: Int, notAssessed: Int)
    /// The run itself failed (`ok: false` without `incomplete`).
    case failed
    /// Complete or not, the run found this many things.
    case findings(Int)
    /// A complete run with no findings.
    case clean
    /// Neither `ok` nor `incomplete` said how the run went (an older CLI).
    case unknown
}

struct ScheduleStatus: Codable {
    let frequency: String?
    let installed: Bool?
    let program: String?
    let program_exists: Bool?
    let licensed: Bool?
    let last_run: ScheduleRun?
    let history_count: Int?
    /// False when the program the launch agent would run is not signed by
    /// QKey; the CLI then refuses to schedule. Absent on an older CLI.
    let program_trusted: Bool?
    let program_team_id: String?
    /// False when Gorse runs from outside /Applications, where an update
    /// (a fresh unzip) breaks the path the launch agent recorded.
    let program_in_applications: Bool?
}

private struct ScheduleHistory: Codable {
    let runs: [ScheduleRun]?
}

private struct ScheduleFailure: Codable {
    let error: String?
    let upgrade_url: String?
}

enum ScheduleDates {
    /// RFC 3339 as the CLI writes it, with or without fractional seconds.
    static func parse(_ text: String?) -> Date? {
        guard let text, !text.isEmpty else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: text) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: text)
    }

    static func relative(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        formatter.dateTimeStyle = .named
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

// MARK: - Model

@MainActor
final class ScheduleModel: ObservableObject {
    static let frequencies = ["off", "daily", "hourly"]
    static let downloadURL = URL(string: "https://www.gorse.is/download")!

    @Published private(set) var status: ScheduleStatus?
    @Published private(set) var history: [ScheduleRun] = []
    @Published private(set) var historyLoaded = false
    @Published private(set) var isBusy = false
    @Published var errorMessage: String?
    /// The frequency the picker shows. Set ahead of the CLI's answer so the
    /// control does not snap back while the launch agent is being written.
    @Published var frequency: String = "off"

    func refresh() async {
        guard let helper = try? ScanRunner.helperURL() else { return }
        guard let (stdout, _, exit) = try? await ScanRunner.execute(helper, arguments: ["schedule", "status", "--json"], timeout: 20),
              case .exited(let code) = exit, code == 0,
              let parsed = try? JSONDecoder().decode(ScheduleStatus.self, from: stdout) else { return }
        apply(parsed)
        if historyLoaded { await loadHistory() }
    }

    func setFrequency(_ wanted: String) async {
        let value = wanted.lowercased()
        guard Self.frequencies.contains(value), !isBusy else { return }
        let previous = frequency
        isBusy = true
        errorMessage = nil
        frequency = value
        defer { isBusy = false }
        do {
            let helper = try ScanRunner.helperURL()
            let (stdout, stderr, exit) = try await ScanRunner.execute(helper, arguments: ["schedule", "set", value, "--json"], timeout: 30)
            if case .timedOut = exit {
                frequency = previous
                errorMessage = "Gorse took too long to change the schedule."
                return
            }
            if let failure = Self.failure(in: stdout) ?? Self.failure(in: stderr) {
                frequency = previous
                errorMessage = failure
                await refresh()
                return
            }
            if case .exited(let code) = exit, code != 0 {
                frequency = previous
                let detail = String(decoding: stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                errorMessage = detail.isEmpty ? "The schedule could not be changed." : String(detail.suffix(400))
                await refresh()
                return
            }
            if let parsed = try? JSONDecoder().decode(ScheduleStatus.self, from: stdout) {
                apply(parsed)
            } else {
                await refresh()
            }
        } catch {
            frequency = previous
            errorMessage = error.localizedDescription
        }
    }

    func loadHistory() async {
        guard let helper = try? ScanRunner.helperURL() else { return }
        guard let (stdout, _, exit) = try? await ScanRunner.execute(helper, arguments: ["schedule", "history", "--json", "--limit", "30"], timeout: 20),
              case .exited(let code) = exit, code == 0,
              let parsed = try? JSONDecoder().decode(ScheduleHistory.self, from: stdout) else { return }
        history = parsed.runs ?? []
        historyLoaded = true
    }

    private func apply(_ parsed: ScheduleStatus) {
        status = parsed
        let reported = (parsed.frequency ?? "off").lowercased()
        frequency = Self.frequencies.contains(reported) ? reported : "off"
    }

    private static func failure(in data: Data) -> String? {
        guard !data.isEmpty, let parsed = try? JSONDecoder().decode(ScheduleFailure.self, from: data),
              let error = parsed.error, !error.isEmpty else { return nil }
        return error
    }

    func openDownload() { NSWorkspace.shared.open(Self.downloadURL) }

    // MARK: Derived text for the view

    var isOn: Bool { frequency != "off" }

    /// The CLI found this copy of Gorse is not signed by QKey, so it will not
    /// schedule it. Shown whether or not a frequency is chosen.
    var programUntrusted: Bool { status?.program_trusted == false }

    var trustWarning: String? {
        guard programUntrusted else { return nil }
        return "This copy of Gorse is not signed by QKey, so scheduled checks are off. Download it again from gorse.is."
    }

    /// Trusted, scheduled, but running from outside /Applications.
    var applicationsHint: String? {
        guard let status, isOn, !programUntrusted, status.program_in_applications == false else { return nil }
        return "Move Gorse to the Applications folder so the schedule survives updates."
    }

    /// "Last check: 3 hours ago · 12 findings · 2 new / 1 worsened", or nil before any run.
    var lastRunLine: String? {
        guard let run = status?.last_run else { return nil }
        var parts: [String] = []
        if let date = run.date {
            parts.append("Last check: \(ScheduleDates.relative(date))")
        } else {
            parts.append("Last check")
        }
        switch run.outcome {
        case .failed:
            parts.append("did not complete")
        case .incomplete:
            parts.append(run.incompleteSummary ?? "incomplete")
            let total = run.counts?.total ?? 0
            if total > 0 { parts.append("\(total) finding\(total == 1 ? "" : "s") so far") }
        case .unknown:
            parts.append("result unknown")
        case .findings, .clean:
            let total = run.counts?.total ?? 0
            parts.append("\(total) finding\(total == 1 ? "" : "s")")
            parts.append("\(run.new ?? 0) new / \(run.worsened ?? 0) worsened")
            if run.unassessedCount > 0 { parts.append("\(run.unassessedCount) not assessed") }
        }
        return parts.joined(separator: " · ")
    }

    /// The last-run line needs attention: the run failed or was incomplete.
    var lastRunNeedsAttention: Bool {
        switch status?.last_run?.outcome {
        case .failed?, .incomplete?: return true
        default: return false
        }
    }

    /// Something the user must fix before scheduled checks will run.
    var warning: String? {
        guard let status, isOn else { return nil }
        if status.program_exists == false { return "Gorse moved. Choose a frequency again to repair the schedule." }
        if status.installed == false { return "The schedule is not installed. Choose a frequency again." }
        return nil
    }
}

// MARK: - View

/// The "Scheduled checks" card under the exposure findings.
struct ScheduleCard: View {
    @ObservedObject var model: ScheduleModel
    @ObservedObject var license: LicenseModel
    @State private var historyExpanded = false

    private var selection: Binding<String> {
        Binding(
            get: { model.frequency },
            set: { value in
                guard value != model.frequency else { return }
                Task { await model.setFrequency(value) }
            }
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("Scheduled checks").font(.subheadline.weight(.semibold))
                if !license.isPaid {
                    Text("Pro")
                        .font(.caption2.weight(.bold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Color.green.opacity(0.18))
                        .foregroundStyle(Color.green)
                        .cornerRadius(4)
                        .accessibilityLabel("Part of Gorse Pro")
                }
                Spacer()
                Picker("Frequency", selection: selection) {
                    Text("Off").tag("off")
                    Text("Daily").tag("daily")
                    Text("Hourly").tag("hourly")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 220)
                // Off can always be chosen, so a lapsed Pro licence or an
                // untrusted copy never leaves a schedule the user cannot
                // turn off. Only Daily and Hourly are gated, and the CLI
                // enforces that too, so a Free user who picks one sees the
                // CLI's refusal and the control snaps back.
                .disabled(model.isBusy || (!model.isOn && (!license.isPaid || model.programUntrusted)))
                .accessibilityLabel("How often Gorse re-runs the check")
                .help(license.isPaid
                      ? "How often Gorse re-runs the check on its own."
                      : (model.isOn ? "Daily and hourly checks are part of Gorse Pro. You can turn the schedule off." : "Scheduled checks are part of Gorse Pro."))
                if model.isBusy { ProgressView().controlSize(.small) }
            }
            Text("Gorse re-runs the check on its own and tells you when something new appears.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if license.isPaid {
                Text("Daily checks run at 9:30 each morning, or the next time the Mac wakes.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            } else {
                HStack(spacing: 8) {
                    Text("Scheduled checks are part of Gorse Pro.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Button("See pricing") { license.openPricing() }
                        .buttonStyle(.link)
                        .font(.caption2)
                        .accessibilityLabel("See Gorse pricing")
                }
            }
            if let warning = model.trustWarning {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Label(warning, systemImage: "xmark.octagon.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                    Button("Download Gorse") { model.openDownload() }
                        .buttonStyle(.link)
                        .font(.caption)
                        .accessibilityLabel("Download Gorse again from gorse.is")
                }
            }
            if let hint = model.applicationsHint {
                Label(hint, systemImage: "folder.badge.questionmark")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            if let warning = model.warning {
                Label(warning, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            if let message = model.errorMessage {
                Text(message).font(.caption).foregroundStyle(.red)
            }
            HStack(spacing: 10) {
                Text(model.lastRunLine ?? "Not run yet")
                    .font(.caption)
                    .foregroundStyle(model.lastRunLine == nil ? AnyShapeStyle(.tertiary)
                        : model.lastRunNeedsAttention ? AnyShapeStyle(Color.orange) : AnyShapeStyle(.secondary))
                    .lineLimit(1)
                if let run = model.status?.last_run, run.outcome == .failed, let message = run.message, !message.isEmpty {
                    Text(message).font(.caption2).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.tail)
                }
                Spacer()
            }
            DisclosureGroup(isExpanded: $historyExpanded) {
                ScheduleHistoryList(runs: model.history, loaded: model.historyLoaded)
            } label: {
                HStack(spacing: 6) {
                    Text("History").font(.caption.weight(.medium))
                    if let count = model.status?.history_count, count > 0 {
                        Text("\(count)").font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
            .accessibilityLabel(historyExpanded ? "Hide the history of checks" : "Show the history of checks")
            .onChange(of: historyExpanded) { expanded in
                if expanded && !model.historyLoaded { Task { await model.loadHistory() } }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Scheduled checks")
    }
}

private struct ScheduleHistoryList: View {
    let runs: [ScheduleRun]
    let loaded: Bool

    var body: some View {
        if !loaded {
            HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Loading…").font(.caption2).foregroundStyle(.secondary) }
                .padding(.vertical, 4)
        } else if runs.isEmpty {
            Text("No checks recorded yet. Run the Fast Scan, or turn on a schedule.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .padding(.vertical, 4)
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(runs) { run in ScheduleHistoryRow(run: run) }
                }
                .padding(.vertical, 4)
            }
            .frame(maxHeight: 160)
        }
    }
}

private struct ScheduleHistoryRow: View {
    let run: ScheduleRun

    var body: some View {
        HStack(spacing: 8) {
            Text(run.date.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? (run.at ?? "Unknown time"))
                .font(.caption)
                .frame(width: 150, alignment: .leading)
                .lineLimit(1)
            switch run.outcome {
            case .incomplete:
                Text(run.incompleteSummary ?? "incomplete")
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .lineLimit(1)
                    .help("This check could not read every location, so it is not a clean result. Anything it did find is shown.")
                severityBadges
            case .failed:
                Text("did not complete").font(.caption2).foregroundStyle(.orange)
            case .findings:
                severityBadges
            case .clean:
                Text("no findings").font(.caption2).foregroundStyle(.secondary)
            case .unknown:
                Text("result unknown").font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
            Text(changes)
                .font(.caption2)
                .foregroundStyle(run.unassessedCount > 0 || run.incomplete == true ? Color.orange : Color.secondary)
                .lineLimit(1)
                .help(run.unassessedCount > 0 ? "Not assessed: earlier findings this run could not look at again. They may still be present." : "")
            if let trigger = run.trigger, !trigger.isEmpty {
                Text(trigger).font(.caption2).foregroundStyle(.tertiary)
            }
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private var severityBadges: some View {
        if let counts = run.counts, counts.total > 0 {
            severity("critical", counts.critical)
            severity("high", counts.high)
            severity("medium", counts.medium)
            severity("low", counts.low)
        }
    }

    @ViewBuilder
    private func severity(_ name: String, _ count: Int?) -> some View {
        if let count, count > 0 {
            HStack(spacing: 3) {
                ExposureSeverityBadge(severity: name)
                Text("\(count)").font(.caption2).foregroundStyle(.secondary)
            }
        }
    }

    private var changes: String {
        var text = "+\(run.new ?? 0) new, \(run.worsened ?? 0) worsened, \(run.resolved ?? 0) resolved"
        // The row's incomplete label already names the unassessed count.
        if run.unassessedCount > 0 && run.incomplete != true { text += ", \(run.unassessedCount) not assessed" }
        return text
    }
}
#endif
