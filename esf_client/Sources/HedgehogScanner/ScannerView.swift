// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Main window: chosen folders on the left, findings on the right.

import SwiftUI

struct ScannerView: View {
    @ObservedObject var model: ScannerModel

    var body: some View {
        HSplitView {
            FolderPane(model: model)
                .frame(minWidth: 240, idealWidth: 280, maxWidth: 360)
            ResultsPane(model: model)
                .frame(minWidth: 460, maxWidth: .infinity)
        }
        .task { await model.loadDefaultPlaces() }
        .onAppear {
            #if DEBUG
            let args = CommandLine.arguments
            if args.contains("--smoke-test") {
                Task {
                    await model.runSmokeTest()
                    NSApplication.shared.terminate(nil)
                }
            }
            #endif
        }
    }
}

// MARK: - Folders

private struct FolderPane: View {
    @ObservedObject var model: ScannerModel
    #if HEDGEHOG_DESKTOP
    @EnvironmentObject var license: LicenseModel
    #endif

    private var proAvailable: Bool {
        #if HEDGEHOG_DESKTOP
        return license.isPaid
        #else
        return false
        #endif
    }

    private func openPricing() {
        #if HEDGEHOG_DESKTOP
        license.openPricing()
        #endif
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(ScannerModel.canScanDefaults ? "Deep scan: files for secrets" : "Folders to scan")
                    .font(.headline)
                Spacer()
                Button {
                    model.chooseFolders()
                } label: {
                    Label("Add", systemImage: "plus")
                }
                .help(ScannerModel.canScanDefaults ? "Add a folder to scan as well" : "Choose folders to scan")
            }
            .padding(12)

            Divider()

            if ScannerModel.canScanDefaults {
                ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Where Gorse looks")
                        .font(.subheadline.weight(.semibold))
                    if model.defaultPlaces.isEmpty {
                        Text("Desktop, Documents (including code checkouts such as GitHub), Downloads and Pictures, the text inside screenshots and photos, and Apple Notes.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        VStack(alignment: .leading, spacing: 7) {
                            ForEach(model.defaultPlaces) { place in
                                HStack(alignment: .top, spacing: 8) {
                                    Image(systemName: place.symbol)
                                        .foregroundStyle(.secondary)
                                        .frame(width: 16)
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(place.label).font(.caption.weight(.semibold))
                                        if let path = place.displayPath, place.kind != "settings" {
                                            Text(path).font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                                        }
                                        if !place.detail.isEmpty {
                                            Text(place.detail).font(.caption2).foregroundStyle(.tertiary)
                                        }
                                    }
                                }
                                .opacity(model.wholeHome ? 0.4 : 1)
                            }
                        }
                    }
                    Toggle(isOn: $model.wholeHome) {
                        VStack(alignment: .leading, spacing: 1) {
                            Text("Whole home folder (Pro)").font(.caption.weight(.semibold))
                            Text("Every folder you own, hidden ones included, instead of the default places. Slower. Part of Gorse Pro.").font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .disabled(model.isScanning || !proAvailable)
                    if !proAvailable {
                        HStack(spacing: 6) {
                            Text("You are on the free plan.").font(.caption2).foregroundStyle(.secondary)
                            Button("Upgrade to Pro") { openPricing() }.buttonStyle(.link).font(.caption2)
                        }
                    }
                    if !model.folders.isEmpty {
                        Divider()
                        Text("Also scan")
                            .font(.subheadline.weight(.semibold))
                        ForEach(model.folders) { folder in
                            let covered = model.isCovered(folder.url)
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: "folder").foregroundStyle(.secondary).frame(width: 16)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(folder.displayName).font(.caption.weight(.semibold))
                                    Text(folder.displayPath).font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                                    if covered {
                                        Text("Already included above").font(.caption2).foregroundStyle(.tertiary)
                                    }
                                }
                                Spacer(minLength: 0)
                                Button { model.remove(folder) } label: {
                                    Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                                }
                                .buttonStyle(.plain)
                                .help("Remove from scan")
                                .disabled(model.isScanning)
                            }
                            .opacity(covered ? 0.5 : 1)
                        }
                    }
                    Text("To scan another folder as well, click Add. If Apple Notes could not be read, give Gorse Full Disk Access in System Settings, Privacy & Security.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .topLeading)
                }
            } else if model.folders.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "folder.badge.plus")
                        .font(.system(size: 36))
                        .foregroundStyle(.secondary)
                    Text("No folders chosen")
                        .font(.subheadline)
                    Text("Add the folders you want checked, such as Documents, Desktop or a project.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    Button("Choose Folders…") { model.chooseFolders() }
                        .buttonStyle(.borderedProminent)
                }
                .padding(20)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(model.folders) { folder in
                        HStack(spacing: 8) {
                            Image(systemName: "folder")
                                .foregroundStyle(.secondary)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(folder.displayName)
                                    .font(.body)
                                    .lineLimit(1)
                                Text(folder.displayPath)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            Spacer()
                            Button {
                                model.remove(folder)
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundStyle(.secondary)
                            }
                            .buttonStyle(.plain)
                            .help("Remove from scan")
                            .disabled(model.isScanning)
                        }
                        .padding(.vertical, 2)
                    }
                }
                .listStyle(.inset)
            }

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                if model.isScanning {
                    Button {
                        model.stopScan()
                    } label: {
                        HStack {
                            ProgressView().controlSize(.small)
                            Text(model.isStopping ? "Stopping, keeping what was found…" : "Stop and Show Results")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .disabled(model.isStopping)
                } else {
                Button {
                    Task { await model.runScan() }
                } label: {
                    HStack {
                        if model.isScanning {
                            ProgressView().controlSize(.small)
                            Text("Scanning…")
                        } else if model.canResume {
                            Label("Resume Scan", systemImage: "play.fill")
                        } else if ScannerModel.canScanDefaults {
                            Label(model.wholeHome ? "Deep Scan, Whole Home" : (model.hasResults ? "Rescan" : "Deep Scan"), systemImage: "magnifyingglass")
                        } else if model.hasResults && !model.pendingFolders.isEmpty {
                            Label("Scan \(model.pendingFolders.count) New Folder\(model.pendingFolders.count == 1 ? "" : "s")", systemImage: "magnifyingglass")
                        } else if model.hasResults {
                            Label("Rescan All", systemImage: "arrow.clockwise")
                        } else {
                            Label("Scan Chosen Folders", systemImage: "magnifyingglass")
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled((model.folders.isEmpty && !ScannerModel.canScanDefaults) || model.isScanning)
                }
                if !ScannerModel.canScanDefaults && model.hasResults && !model.pendingFolders.isEmpty {
                    Button("Rescan All") { Task { await model.runScan(rescanAll: true) } }
                        .controlSize(.small)
                        .disabled(model.isScanning)
                }

                Text(ScannerModel.canScanDefaults
                     ? "Files are read on this Mac and nothing leaves it. No secret is shown in full."
                     : "Only the folders above are read, and nothing leaves this Mac. No secret is shown in full.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .padding(12)
        }
    }
}

// MARK: - Results

private struct ResultsPane: View {
    @ObservedObject var model: ScannerModel

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Findings")
                        .font(.headline)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if model.report != nil {
                    Button("Clear") { model.clearResults() }
                        .disabled(model.isScanning)
                }
            }
            .padding(12)

            Divider()

            if let message = model.errorMessage {
                Placeholder(systemImage: "exclamationmark.triangle", tint: .orange,
                            title: "The scan could not complete", detail: message)
            } else if model.isScanning && !model.liveFindings.isEmpty {
                // Findings appear as they are found; the scan carries on above.
                VStack(spacing: 0) {
                    HStack(alignment: .top, spacing: 8) {
                        ProgressView().controlSize(.small)
                        ScanProgressDetail(model: model, centered: false)
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, 12).padding(.vertical, 8)
                    Divider()
                    FindingsList(sections: model.liveFindings.sections(bySeverity: false), model: model)
                }
            } else if model.isScanning {
                VStack(spacing: 10) {
                    ProgressView()
                    ScanProgressDetail(model: model, centered: true)
                        .frame(maxWidth: 480)
                }
                .padding(24)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let report = model.report {
                VStack(spacing: 0) {
                    if report.notesUnreadable {
                        NotesAccessBanner { model.openFullDiskAccessSettings() }
                        Divider()
                    }
                    switch (report.findings.isEmpty, report.coverageState) {
                    case (true, .allClear(let filesChecked)):
                        Placeholder(systemImage: "checkmark.shield", tint: .green,
                                    title: "No secrets found",
                                    detail: (["\(filesChecked == 1 ? "1 readable file" : "\(filesChecked) readable files") in the chosen folders \(filesChecked == 1 ? "was" : "were") read, and nothing matched a known secret or sensitive-content pattern."] + report.coverageNotes).joined(separator: " "))
                    case (true, .gaps(let headline, let reasons)):
                        GapsPlaceholder(headline: headline, reasons: reasons)
                    case (false, .gaps(let headline, let reasons)):
                        GapsBanner(headline: headline, reasons: reasons)
                        Divider()
                        FindingsList(sections: report.findings.sections(bySeverity: true), model: model)
                    case (false, .allClear):
                        FindingsList(sections: report.findings.sections(bySeverity: true), model: model)
                    }
                }
            } else {
                Placeholder(systemImage: "doc.text.magnifyingglass", tint: .secondary,
                            title: "Ready to scan",
                            detail: ScannerModel.canScanDefaults
                                ? "Click Deep Scan. Gorse reads your documents, downloads, code, screenshots and notes for API keys, passwords, private keys, seed phrases, card numbers and other sensitive content."
                                : "Choose one or more folders, then click Scan Chosen Folders. Gorse looks for API keys, passwords, private keys, seed phrases, card numbers and other sensitive content, including the text in screenshots and photos.")
            }
        }
    }

    private var subtitle: String {
        if model.isScanning {
            return "Scanning… " + model.liveFindings.tally.summary(empty: "nothing found yet")
        }
        guard let report = model.report else { return "Nothing scanned yet" }
        let seconds = max(report.elapsed_secs, 1)
        var text = "\(report.findings.tally.summary(empty: "Nothing found")) in \(seconds)s"
        if report.interrupted { text += " (stopped early)" }
        if let n = report.coverage?.notes_read {
            text += n == 1 ? " · 1 Apple Note read" : " · \(n.formatted()) Apple Notes read"
        }
        if case .gaps = report.coverageState { text += " · some files not checked" }
        if let date = model.lastScanDate {
            text += " · " + date.formatted(date: .abbreviated, time: .shortened)
        }
        return text
    }
}

/// Amber "finished with gaps" state shown instead of the green all-clear
/// when the scan had no findings but did not check everything.
struct GapsPlaceholder: View {
    let headline: String
    let reasons: [String]

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "exclamationmark.shield")
                .font(.system(size: 40))
                .foregroundStyle(.orange)
            Text("Scan finished with gaps")
                .font(.headline)
            Text("No secrets were found in the files that were checked, but the scan did not cover everything.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 380)
            GapsDetail(headline: headline, reasons: reasons)
                .frame(maxWidth: 420)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityIdentifier("scan-gaps")
    }
}

/// Compact amber strip above the findings list when there were findings
/// and the scan also left gaps.
struct GapsBanner: View {
    let headline: String
    let reasons: [String]
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.shield")
                    .foregroundStyle(.orange)
                Text("Scan finished with gaps")
                    .font(.subheadline.weight(.semibold))
                Text(headline)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                Button(expanded ? "Hide" : "Why?") { expanded.toggle() }
                    .buttonStyle(.link)
                    .font(.caption)
            }
            if expanded {
                ForEach(reasons, id: \.self) { reason in
                    Label {
                        Text(reason).font(.caption)
                    } icon: {
                        Image(systemName: "minus").font(.caption2)
                    }
                    .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.10))
    }
}

private struct GapsDetail: View {
    let headline: String
    let reasons: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(headline)
                .font(.caption.weight(.semibold))
            ForEach(reasons, id: \.self) { reason in
                HStack(alignment: .top, spacing: 6) {
                    Text("•").font(.caption)
                    Text(reason).font(.caption)
                }
                .foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.10))
        .cornerRadius(8)
    }
}

private struct Placeholder: View {
    let systemImage: String
    let tint: Color
    let title: String
    let detail: String

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.system(size: 40))
                .foregroundStyle(tint)
            Text(title)
                .font(.headline)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 380)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Credentials first, then sensitive content, each with its count.
private struct FindingsList: View {
    let sections: [FindingSection]
    @ObservedObject var model: ScannerModel

    var body: some View {
        List {
            ForEach(sections) { section in
                Section {
                    ForEach(section.findings) { finding in
                        FindingRow(finding: finding, model: model)
                    }
                } header: {
                    VStack(alignment: .leading, spacing: 1) {
                        HStack {
                            Text(section.group.title)
                            Spacer()
                            Text("\(section.findings.count)")
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                        }
                        Text(section.group.detail)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .listStyle(.inset)
    }
}

/// Counts, bar, current step or folder, and disk share while a scan runs.
/// One view for both the empty and the live-findings states, so the two
/// never show different lines.
private struct ScanProgressDetail: View {
    @ObservedObject var model: ScannerModel
    let centered: Bool

    var body: some View {
        VStack(alignment: centered ? .center : .leading, spacing: 3) {
            if let p = model.progress {
                Text(model.progressLine)
                    .font(.caption.weight(.semibold).monospacedDigit())
                    .multilineTextAlignment(centered ? .center : .leading)
                    .fixedSize(horizontal: false, vertical: true)
                if let f = model.fractionDone { ProgressView(value: f).frame(maxWidth: 360) }
                if let step = ScannerModel.stepDescription(p.phase, imagesKnown: model.images != nil) {
                    Text(step).font(.caption2).foregroundStyle(.secondary)
                } else if p.phase == nil && !p.displayDir.isEmpty {
                    Text("Reading \(p.displayDir)")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                if p.phase == nil, let percent = model.diskCoverage {
                    HStack(spacing: 4) {
                        Text("Covers about \(percent)% of what is on this disk.")
                            .font(.caption2).foregroundStyle(.secondary)
                        if ScannerModel.canScanDefaults && !model.wholeHome {
                            Button("Whole-disk scan with Pro") { NSWorkspace.shared.open(URL(string: "https://www.gorse.is/pricing")!) }
                                .buttonStyle(.link).font(.caption2)
                        }
                    }
                }
            } else {
                Text("Starting…").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

/// Shown above the results when the scan could not open Apple Notes
/// because Gorse has no Full Disk Access.
struct NotesAccessBanner: View {
    let openSettings: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "note.text")
                .foregroundStyle(.orange)
                .font(.title3)
            VStack(alignment: .leading, spacing: 3) {
                Text("Apple Notes could not be read. Gorse needs Full Disk Access to check your notes.")
                    .font(.subheadline.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                Text("Turn on Gorse, then run the scan again.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Button("Open Privacy Settings", action: openSettings)
                .controlSize(.small)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.10))
        .accessibilityIdentifier("notes-unreadable")
    }
}

private struct FindingRow: View {
    let finding: ScanFinding
    @ObservedObject var model: ScannerModel

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            // What it looks like and how sure, never the secret itself.
            HStack(spacing: 6) {
                SeverityBadge(severity: finding.severity)
                    .fixedSize()
                Text("Looks like: \(finding.kind)")
                    .font(.callout.weight(.semibold))
                    .lineLimit(1)
                if let likelihood = finding.likelihood {
                    Text("\(likelihood)% sure")
                        .font(.caption.weight(.semibold).monospacedDigit())
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.15))
                        .cornerRadius(4)
                        .fixedSize()
                        .help("How sure Gorse is that this match is real, from how exact the match is and where it sits (a comment or a test file counts against it). An estimate.")
                }
                Spacer()
                Button {
                    model.reveal(finding)
                } label: {
                    Image(systemName: "arrow.right.circle")
                }
                .buttonStyle(.plain)
                .help(finding.isAppleNote ? "Open Notes" : "Show in Finder")
            }
            if let reason = finding.reason {
                Text(reason.prefix(1).uppercased() + reason.dropFirst())
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 6) {
                Image(systemName: finding.isAppleNote ? "note.text" : "doc")
                    .font(.caption2).foregroundStyle(.tertiary)
                Text(shortPath)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if finding.line > 0 && !finding.isAppleNote {
                    Text("line \(finding.line)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .fixedSize()
                }
            }
        }
        .padding(.vertical, 3)
        .contextMenu {
            Button(finding.isAppleNote ? "Open Notes" : "Show in Finder") { model.reveal(finding) }
            if let guide = finding.rotation_guide, let url = URL(string: guide) {
                Button("How to rotate this key…") { NSWorkspace.shared.open(url) }
            }
            if !finding.isAppleNote {
                Button("Copy Path") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(finding.path, forType: .string)
                }
            }
        }
    }

    private var shortPath: String {
        if finding.isAppleNote { return "Apple Notes" }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        guard let folder = model.folders.first(where: { finding.path.hasPrefix($0.url.path + "/") }) else {
            return finding.path.hasPrefix(home + "/") ? "~" + finding.path.dropFirst(home.count) : finding.path
        }
        return folder.displayName + String(finding.path.dropFirst(folder.url.path.count))
    }
}

private struct SeverityBadge: View {
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
