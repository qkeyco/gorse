// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// "What this Mac reaches": the exposure check as a window. Summary tiles on
// top, findings grouped by severity below, a saved HTML report on request.

import SwiftUI

struct ExposureView: View {
    @ObservedObject var model: ExposureModel
    #if HEDGEHOG_DESKTOP
    @EnvironmentObject var schedule: ScheduleModel
    @EnvironmentObject var license: LicenseModel
    #endif

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
            #if HEDGEHOG_DESKTOP
            Divider()
            ScheduleCard(model: schedule, license: license)
            #endif
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Fast scan: what this Mac reaches")
                        .font(.headline)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("Fast scan: the places tools keep credentials, about 60 known locations, not every file. Deep Scan reads everything else.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                Spacer()
                Text("Gorse \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "")")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.trailing, 6)
                if model.report != nil {
                    Button("Open Report") { model.openReport() }
                        .disabled(model.reportHTML == nil)
                    Button("Save Report…") { model.saveReport() }
                        .disabled(model.reportHTML == nil)
                }
                #if HEDGEHOG_DESKTOP
                Button {
                    model.verifyTapped()
                } label: {
                    if model.isRunning && model.isVerifying {
                        HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Verifying…") }
                    } else {
                        Label("Verify with providers", systemImage: "checkmark.seal")
                    }
                }
                // Stays enabled on Free so the journey is visible: the CLI
                // refuses and the pricing message appears below.
                .disabled(model.isRunning)
                .help(license.isPaid
                      ? "Ask your own provider tools, read-only, which findings are real."
                      : "Verify is part of Gorse Pro. Choosing it shows what it does and where to get a key.")
                .accessibilityLabel("Verify with providers")
                #endif
                Button {
                    Task { await model.runCheck() }
                } label: {
                    if checkInProgress {
                        HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Checking…") }
                    } else {
                        Label(model.report == nil ? "Run Fast Scan" : "Run Again", systemImage: "key.viewfinder")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isRunning)
                .keyboardShortcut("r")
            }
            #if HEDGEHOG_DESKTOP
            if model.showVerifyExplanation {
                VerifyExplanation(model: model)
            }
            if let message = model.proMessage {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Label(message, systemImage: "lock")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button("See pricing") { license.openPricing() }
                        .buttonStyle(.link)
                        .font(.caption)
                        .accessibilityLabel("See Gorse pricing")
                    Spacer()
                    Button { model.dismissProMessage() } label: { Image(systemName: "xmark.circle") }
                        .buttonStyle(.plain)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("Dismiss")
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.green.opacity(0.08))
                .cornerRadius(6)
            }
            #endif
            if let report = model.report {
                #if HEDGEHOG_DESKTOP
                if report.isIncomplete {
                    IncompleteCheckBanner(report: report)
                }
                if report.unassessedCount > 0 {
                    UnassessedFindingsSection(report: report)
                }
                #endif
                SummaryStrip(report: report)
            }
        }
        .padding(12)
    }

    /// The report could not read every known credential location (desktop
    /// build only: the sandboxed Scanner never runs the check).
    private var reportIncomplete: Bool {
        #if HEDGEHOG_DESKTOP
        return model.report?.isIncomplete == true
        #else
        return false
        #endif
    }

    /// The plain check is running (not Verify, which has its own button state).
    private var checkInProgress: Bool {
        #if HEDGEHOG_DESKTOP
        return model.isRunning && !model.isVerifying
        #else
        return model.isRunning
        #endif
    }

    private var subtitle: String {
        guard let report = model.report else {
            return "If this laptop were stolen tonight, what could they get into?"
        }
        var parts: [String] = []
        parts.append("\(report.summary.credentials) credential\(report.summary.credentials == 1 ? "" : "s") found")
        #if HEDGEHOG_DESKTOP
        if report.unassessedCount > 0 { parts.append("\(report.unassessedCount) not assessed") }
        if report.isIncomplete { parts.append("incomplete check") }
        #endif
        if let date = model.lastRunDate { parts.append(date.formatted(date: .abbreviated, time: .shortened)) }
        if let version = report.cliVersion { parts.append("Gorse \(version)") }
        if report.verified != true { parts.append("not verified with providers") }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder
    private var content: some View {
        if let message = model.errorMessage {
            ExposurePlaceholder(systemImage: "exclamationmark.triangle", tint: .orange,
                                title: "The check could not complete", detail: message)
        } else if model.isRunning {
            VStack(spacing: 10) {
                ProgressView()
                Text(runningText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 380)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let report = model.report {
            if report.findings.isEmpty {
                #if HEDGEHOG_DESKTOP
                if reportIncomplete {
                    // Not an all-clear: the credential may be in the file that could not be read.
                    ExposurePlaceholder(systemImage: "exclamationmark.triangle", tint: .orange,
                                        title: "Incomplete check",
                                        detail: "No credentials were found in the locations Gorse could read, but "
                                            + incompleteCount(report)
                                            + " could not be read, so this is not an all-clear. "
                                            + "Fix the access and run the check again. "
                                            + (report.notes?.joined(separator: " ") ?? ""))
                } else {
                    cleanPlaceholder(report)
                }
                #else
                cleanPlaceholder(report)
                #endif
            } else {
                ExposureList(model: model, notes: report.notes ?? [])
            }
        } else {
            ExposurePlaceholder(systemImage: "key.viewfinder", tint: .secondary,
                                title: "Checking this Mac…",
                                detail: "Gorse reads the credential files, agent settings and signed-in sessions it recognises on this Mac, works out what each one opens, and shows the paths to your production systems, code and funds. It reads only, prints no secret and sends nothing anywhere.")
        }
    }

    /// The green all-clear, shown only when every known location was read.
    private func cleanPlaceholder(_ report: ExposureReport) -> some View {
        ExposurePlaceholder(systemImage: "checkmark.shield", tint: .green,
                            title: "No credentials found",
                            detail: "Nothing on this Mac matched a credential location Gorse knows. "
                                + (report.notes?.joined(separator: " ") ?? ""))
    }

    #if HEDGEHOG_DESKTOP
    /// "3 credential locations" / "1 credential location" / "a credential location" (flag set, none listed).
    private func incompleteCount(_ report: ExposureReport) -> String {
        let n = (report.coverage_failures ?? []).count
        if n == 0, report.unassessedCount > 0 { return "a source an earlier check covered" }
        if n == 0 { return "a credential location" }
        return "\(n) credential location\(n == 1 ? "" : "s")"
    }
    #endif

    private var runningText: String {
        #if HEDGEHOG_DESKTOP
        if model.isVerifying {
            return "Reading credential files on this Mac, then asking your installed provider tools read-only questions. Nothing is sent to Gorse…"
        }
        #endif
        return "Reading credential files, agent settings and signed-in sessions on this Mac…"
    }
}

#if HEDGEHOG_DESKTOP
/// Shown once, before the first Verify run, so the user knows what it does
/// before any provider tool is asked anything.
private struct VerifyExplanation: View {
    @ObservedObject var model: ExposureModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Verify with providers", systemImage: "checkmark.seal")
                .font(.caption.weight(.semibold))
            Text(ExposureModel.verifyExplanation)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Not now") { model.showVerifyExplanation = false }
                    .controlSize(.small)
                Button("Verify now") { model.confirmVerify() }
                    .controlSize(.small)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.08))
        .cornerRadius(6)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("What Verify does")
    }
}

/// Amber "Incomplete check" banner: the locations the CLI could not read,
/// with the reason. Paths only; the contents of a credential file are never
/// shown. Sits above the summary tiles so it is read before any count.
private struct IncompleteCheckBanner: View {
    let report: ExposureReport
    @State private var showAll = false

    private static let preview = 6

    private var failures: [CoverageFailure] { report.coverage_failures ?? [] }
    private var unavailable: [SourceUnavailable] { report.sources_unavailable ?? [] }

    private var headline: String {
        let n = failures.count
        if n == 0, report.unassessedCount > 0 {
            return "Gorse could not assess every source an earlier check covered, so this check is not complete."
        }
        if n == 0 { return "Gorse could not read every credential location, so this check is not complete." }
        return "Gorse could not read \(n) credential location\(n == 1 ? "" : "s"), so this check is not complete."
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Incomplete check", systemImage: "exclamationmark.triangle.fill")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.orange)
            Text(headline)
                .font(.caption)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(showAll ? failures : Array(failures.prefix(Self.preview))) { failure in
                HStack(alignment: .top, spacing: 6) {
                    Text(failure.displayLocation)
                        .font(.system(.caption2, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text("— " + failure.reason)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                .accessibilityElement(children: .combine)
            }
            if failures.count > Self.preview {
                Button(showAll ? "Show fewer" : "Show all \(failures.count) locations") { showAll.toggle() }
                    .buttonStyle(.link)
                    .font(.caption2)
            }
            ForEach(unavailable) { source in
                HStack(alignment: .top, spacing: 6) {
                    Text("Not assessed: \(source.source)")
                        .font(.caption2)
                    Text("— " + source.reason)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                .accessibilityElement(children: .combine)
            }
            Text("Counts and findings below come from the locations that could be read. Fix the access and run the check again.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.12))
        .cornerRadius(6)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Incomplete check. \(headline)")
    }
}

/// "Not assessed in this run (N)": findings an earlier recorded check made
/// whose source this run could not assess. They are shown as earlier
/// findings that may still be present, with the severity they had then,
/// never as resolved.
private struct UnassessedFindingsSection: View {
    let report: ExposureReport
    @State private var showAll = false

    private static let preview = 6

    private var entries: [ChangeEntry] {
        report.unassessed.sorted {
            (SeverityOrder.rank($0.lastSeverity), $0.title) < (SeverityOrder.rank($1.lastSeverity), $1.title)
        }
    }

    var body: some View {
        let count = report.unassessedCount
        VStack(alignment: .leading, spacing: 6) {
            Label("Not assessed in this run (\(count))", systemImage: "questionmark.circle.fill")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.orange)
            Text("An earlier check found \(count == 1 ? "this credential" : "these credentials"). This run could not look again, so \(count == 1 ? "it" : "they") may still be present. Not resolved.")
                .font(.caption)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(showAll ? entries : Array(entries.prefix(Self.preview))) { entry in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    ExposureSeverityBadge(severity: entry.lastSeverity)
                        .help("Severity when it was last assessed")
                    VStack(alignment: .leading, spacing: 1) {
                        HStack(spacing: 4) {
                            Text(entry.title).font(.caption2.weight(.medium)).lineLimit(1)
                            if let kind = entry.kind, kind != entry.title {
                                Text(kind).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }
                        if let location = entry.displayLocation {
                            Text(location)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        if let reason = entry.reason {
                            Text("Not assessed: " + reason)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                        }
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Earlier \(entry.lastSeverity) finding, not assessed in this run: \(entry.title)\(entry.displayLocation.map { ", " + $0 } ?? "")\(entry.reason.map { ". " + $0 } ?? "")")
            }
            if entries.count > Self.preview {
                Button(showAll ? "Show fewer" : "Show all \(entries.count)") { showAll.toggle() }
                    .buttonStyle(.link)
                    .font(.caption2)
            }
            if count > entries.count {
                Text("\(count - entries.count) more not listed here; see the saved report.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.06))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.orange.opacity(0.35), lineWidth: 1))
        .cornerRadius(6)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Not assessed in this run, \(count) earlier finding\(count == 1 ? "" : "s") that may still be present")
    }
}
#endif

private struct SummaryStrip: View {
    let report: ExposureReport

    private var summary: ExposureSummary { report.summary }

    /// Counts from a check that could not read every location are shown
    /// faded, so a low number is not mistaken for the whole picture.
    private var dimmed: Bool {
        #if HEDGEHOG_DESKTOP
        return report.isIncomplete
        #else
        return false
        #endif
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Tile(value: summary.credentials, label: "Credentials", tint: .secondary)
                Tile(value: summary.by_severity?.critical ?? 0, label: "Critical", tint: .red)
                #if HEDGEHOG_DESKTOP
                // Two different counts: findings with any path to a production
                // target (computed from the findings) and the CLI's narrower
                // count of indirect signing and financial paths.
                Tile(value: report.findingsReachingProduction, label: "Findings reaching production", tint: .red)
                Tile(value: summary.critical_indirect_paths ?? 0, label: "Critical indirect paths", tint: .orange)
                #else
                Tile(value: summary.critical_indirect_paths ?? 0, label: "Paths to production", tint: .orange)
                #endif
                Tile(value: summary.persistent_access_risks ?? 0, label: "Rotate / revoke needed", tint: .purple)
                Tile(value: summary.privileged_credentials ?? 0, label: "Privileged", tint: .blue)
            }
            .opacity(dimmed ? 0.45 : 1)
            #if HEDGEHOG_DESKTOP
            if report.unassessedCount > 0 {
                Text("+ \(report.unassessedCount) not assessed: earlier findings not counted above that may still be present")
                    .font(.caption2)
                    .foregroundStyle(.orange)
            }
            if dimmed {
                Text("counts from an incomplete check")
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .accessibilityLabel("These counts come from an incomplete check")
            }
            if let counts = summary.verification_counts, showsVerification(counts) {
                // The CLI's own tally: a provider query that failed is a
                // failure, not an inference, and is counted as one.
                let failed = counts.failed ?? 0
                Label("Verified with providers: " + counts.line(separator: " · "),
                      systemImage: failed > 0 ? "checkmark.seal" : "checkmark.seal.fill")
                    .font(.caption)
                    .foregroundStyle(failed > 0 ? .orange : .secondary)
                    .accessibilityLabel("Verified with providers: " + counts.line(separator: ", "))
            } else if report.verified == true {
                // Older CLI without verification_counts: derive from confidence.
                let counts = report.confidenceCounts
                Label("Verified with providers: \(counts.confirmed) confirmed · \(counts.inferred) inferred · \(counts.unchecked) could not be checked",
                      systemImage: "checkmark.seal.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Verified with providers: \(counts.confirmed) confirmed, \(counts.inferred) inferred, \(counts.unchecked) could not be checked")
            }
            #endif
        }
    }

    #if HEDGEHOG_DESKTOP
    /// Show the tally once Verify ran, or whenever a provider was actually
    /// asked; an all-not-attempted tally from a plain check says nothing.
    private func showsVerification(_ counts: VerificationCounts) -> Bool {
        report.verified == true || counts.attempted > 0
    }
    #endif

    private struct Tile: View {
        let value: Int
        let label: String
        let tint: Color

        var body: some View {
            VStack(alignment: .leading, spacing: 2) {
                Text("\(value)")
                    .font(.system(size: 22, weight: .semibold, design: .rounded))
                    .foregroundStyle(value > 0 ? tint : .secondary)
                Text(label)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(tint.opacity(value > 0 ? 0.10 : 0.04))
            .cornerRadius(8)
        }
    }
}

private struct ExposureList: View {
    @ObservedObject var model: ExposureModel
    let notes: [String]

    var body: some View {
        List {
            ForEach(model.grouped, id: \.severity) { group in
                Section {
                    ForEach(group.findings) { finding in
                        ExposureRow(finding: finding, model: model)
                    }
                } header: {
                    HStack {
                        Text(group.severity.capitalized)
                        Spacer()
                        Text("\(group.findings.count)").foregroundStyle(.secondary)
                    }
                }
            }
            if !notes.isEmpty {
                Section("Notes") {
                    ForEach(notes, id: \.self) { note in
                        Text(note).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .listStyle(.inset)
    }
}

private struct ExposureRow: View {
    let finding: ExposureFinding
    @ObservedObject var model: ExposureModel
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                ExposureSeverityBadge(severity: finding.severity)
                Text(finding.kind_label ?? finding.name)
                    .font(.callout.weight(.medium))
                    .lineLimit(1)
                if finding.name != (finding.kind_label ?? finding.name) {
                    Text(finding.name)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                if finding.survivesWipe {
                    Label("Rotate / revoke needed", systemImage: "arrow.triangle.2.circlepath")
                        .font(.caption2)
                        .foregroundStyle(.purple)
                        .labelStyle(.titleAndIcon)
                        .help("Wiping the laptop does not remove this access. Rotate or revoke the credential at the server or service that issued it. " + (finding.persistence?.label ?? ""))
                }
                if finding.expired == true {
                    Text("expired").font(.caption2).foregroundStyle(.secondary)
                }
                Button { expanded.toggle() } label: {
                    Image(systemName: expanded ? "chevron.up.circle" : "info.circle")
                }
                .buttonStyle(.plain)
                .help(expanded ? "Hide details" : "Why, and what to do")
            }
            if !finding.displayLocation.isEmpty {
                Text(finding.displayLocation)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            ForEach(Array(finding.sortedPaths.prefix(expanded ? 20 : 2).enumerated()), id: \.offset) { _, path in
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "arrow.turn.down.right")
                        .font(.caption2)
                        .foregroundStyle(path.target_production == true ? .red : .secondary)
                    Text(pathLine(path))
                        .font(.caption)
                        .foregroundStyle(path.target_production == true ? .primary : .secondary)
                        .lineLimit(expanded ? 3 : 1)
                }
            }
            if !expanded, finding.sortedPaths.count > 2 {
                Text("and \(finding.sortedPaths.count - 2) more")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
            if expanded {
                let unmarked = finding.sortedPaths.filter { $0.target_production != true }.map(\.target)
                if !unmarked.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Is one of these a production system? Gorse scores what it cannot identify as ordinary; tell it and it re-scores.")
                            .font(.caption2).foregroundStyle(.secondary)
                        HStack(spacing: 6) {
                            ForEach(Array(Set(unmarked)).sorted(), id: \.self) { target in
                                Button("Mark \(target) as production") { Task { await model.markProduction(target) } }
                                    .controlSize(.small)
                                    .disabled(model.isRunning)
                            }
                        }
                    }
                }
                if let reasons = finding.reasons, !reasons.isEmpty {
                    DetailBlock(title: "Why it matters", lines: reasons)
                }
                if let remediation = finding.remediation, !remediation.isEmpty {
                    DetailBlock(title: "What to do", lines: remediation)
                }
                if let evidence = finding.evidence, !evidence.isEmpty {
                    DetailBlock(title: "Evidence", lines: evidence)
                }
                #if HEDGEHOG_DESKTOP
                if let line = finding.verification?.line {
                    Label(line, systemImage: finding.verification?.isFailed == true
                          ? "exclamationmark.triangle"
                          : (finding.verification?.isProviderConfirmed == true ? "checkmark.seal" : "info.circle"))
                        .font(.caption2)
                        .foregroundStyle(finding.verification?.isFailed == true ? .orange : .secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                #endif
                HStack(spacing: 10) {
                    if let confidence = finding.confidence { Text("confidence \(confidence)") }
                    #if HEDGEHOG_DESKTOP
                    if let source = finding.source, !source.isEmpty { Text("source \(source)") }
                    #endif
                    if let lifetime = finding.lifetime, !lifetime.isEmpty { Text("lifetime \(lifetime)") }
                    if let identity = finding.identity, !identity.isEmpty { Text(identity).lineLimit(1).truncationMode(.middle) }
                }
                .font(.caption2)
                .foregroundStyle(.tertiary)
            }
        }
        .padding(.vertical, 4)
        .contextMenu {
            Button("Show in Finder") { model.reveal(finding) }
            if let location = finding.location, !location.isEmpty {
                Button("Copy Location") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(location, forType: .string)
                }
            }
        }
    }

    private func pathLine(_ path: ExposurePath) -> String {
        var text = path.target
        if let outcome = path.outcome_label, !outcome.isEmpty { text += ": " + outcome }
        if let hops = path.hops, hops > 1 { text += " (\(hops) hops)" }
        if path.target_production == true { text += " · production" }
        return text
    }
}

private struct DetailBlock: View {
    let title: String
    let lines: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption.weight(.semibold))
            ForEach(lines, id: \.self) { line in
                HStack(alignment: .top, spacing: 6) {
                    Text("•").font(.caption)
                    Text(line).font(.caption)
                }
                .foregroundStyle(.secondary)
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.06))
        .cornerRadius(6)
    }
}

private struct ExposurePlaceholder: View {
    let systemImage: String
    let tint: Color
    let title: String
    let detail: String

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.system(size: 40))
                .foregroundStyle(tint)
            Text(title).font(.headline)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ExposureSeverityBadge: View {
    let severity: String

    var body: some View {
        Text(severity.uppercased())
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(color.opacity(0.18))
            .foregroundStyle(color)
            .cornerRadius(3)
    }

    private var color: Color {
        switch severity.lowercased() {
        case "critical": return .red
        case "high": return .orange
        case "medium": return .yellow
        default: return .blue
        }
    }
}
