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
        .onAppear {
            #if DEBUG
            let args = CommandLine.arguments
            if let index = args.firstIndex(of: "--smoke-test"), args.indices.contains(index + 1) {
                let output = args[index + 1]
                Task {
                    await model.runSmokeTest(outputPath: output)
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
    @EnvironmentObject var engines: EngineModel
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
                .help("Choose folders to scan")
            }
            .padding(12)

            Divider()

            if model.folders.isEmpty && ScannerModel.canScanDefaults {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Where Gorse looks")
                        .font(.subheadline.weight(.semibold))
                    Text("Desktop, Documents (including code checkouts such as GitHub), Downloads and Pictures, the text inside screenshots and photos, and Apple Notes.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
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
                    Text("To look somewhere else instead, add folders with the + button. If Apple Notes could not be read, give Gorse Full Disk Access in System Settings, Privacy & Security.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                    #if HEDGEHOG_DESKTOP
                    EngineCard(model: engines)
                    #endif
                }
                .padding(14)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
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
                Button {
                    Task { await model.runScan() }
                } label: {
                    HStack {
                        if model.isScanning {
                            ProgressView().controlSize(.small)
                            Text("Scanning…")
                        } else if model.folders.isEmpty && ScannerModel.canScanDefaults {
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
                if model.hasResults && !model.pendingFolders.isEmpty {
                    Button("Rescan All") { Task { await model.runScan(rescanAll: true) } }
                        .controlSize(.small)
                        .disabled(model.isScanning)
                }

                Text(model.folders.isEmpty && ScannerModel.canScanDefaults
                     ? "Files are read on this Mac and nothing leaves it. No secret is shown in full."
                     : "Only the folders above are read. Results stay on this Mac.")
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
            } else if model.isScanning {
                VStack(spacing: 10) {
                    ProgressView()
                    if let p = model.progress {
                        if let phase = p.phase {
                            Text(phase == "images" ? "Reading the text inside pictures…" : phase == "notes" ? "Reading Apple Notes…" : phase == "trufflehog" ? "Running TruffleHog's detectors…" : "Finishing…")
                                .font(.caption).foregroundStyle(.secondary)
                        } else {
                            Text("\(p.filesScanned.formatted()) file\(p.filesScanned == 1 ? "" : "s") read · \(p.findings) finding\(p.findings == 1 ? "" : "s") so far")
                                .font(.caption.weight(.semibold).monospacedDigit())
                            Text(p.displayDir)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .frame(maxWidth: 480)
                        }
                    } else {
                        Text("Starting…").font(.caption).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let report = model.report {
                switch (report.findings.isEmpty, report.coverageState) {
                case (true, .allClear(let filesChecked)):
                    Placeholder(systemImage: "checkmark.shield", tint: .green,
                                title: "No secrets found",
                                detail: (["\(filesChecked == 1 ? "1 readable file" : "\(filesChecked) readable files") in the chosen folders \(filesChecked == 1 ? "was" : "were") read, and nothing matched a known secret or sensitive-content pattern."] + report.coverageNotes).joined(separator: " "))
                case (true, .gaps(let headline, let reasons)):
                    GapsPlaceholder(headline: headline, reasons: reasons)
                case (false, .gaps(let headline, let reasons)):
                    VStack(spacing: 0) {
                        GapsBanner(headline: headline, reasons: reasons)
                        Divider()
                        FindingsList(findings: report.findings, model: model)
                    }
                case (false, .allClear):
                    FindingsList(findings: report.findings, model: model)
                }
            } else {
                Placeholder(systemImage: "doc.text.magnifyingglass", tint: .secondary,
                            title: "Ready to scan",
                            detail: ScannerModel.canScanDefaults
                                ? "Click Deep Scan. Gorse reads your documents, downloads, code, screenshots and notes for API keys, passwords, private keys, seed phrases, card numbers and other sensitive content."
                                : "Choose one or more folders, then click Run Scan. Gorse looks for API keys, passwords, private keys, card numbers and other sensitive content.")
            }
        }
    }

    private var subtitle: String {
        guard let report = model.report else { return "Nothing scanned yet" }
        let seconds = max(report.elapsed_secs, 1)
        var text = "\(report.total) finding\(report.total == 1 ? "" : "s") in \(seconds)s"
        if report.interrupted { text += " (stopped early)" }
        if let th = report.engines?.first(where: { $0.name == "trufflehog" }) {
            text += th.error == nil ? " · with TruffleHog \(th.version ?? "")" : " · TruffleHog failed"
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
                    .lineLimit(1)
                Spacer()
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

private struct FindingsList: View {
    let findings: [ScanFinding]
    @ObservedObject var model: ScannerModel

    private var grouped: [(String, [ScanFinding])] {
        Dictionary(grouping: findings, by: \.category)
            .sorted { lhs, rhs in
                lhs.value.count != rhs.value.count ? lhs.value.count > rhs.value.count : lhs.key < rhs.key
            }
    }

    var body: some View {
        List {
            ForEach(grouped, id: \.0) { category, items in
                Section {
                    ForEach(items) { finding in
                        FindingRow(finding: finding, model: model)
                    }
                } header: {
                    HStack {
                        Text(category)
                        Spacer()
                        Text("\(items.count)")
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .listStyle(.inset)
    }
}

private struct FindingRow: View {
    let finding: ScanFinding
    @ObservedObject var model: ScannerModel

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                SeverityBadge(severity: finding.severity)
                Text(shortPath)
                    .font(.callout)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if finding.line > 0 {
                    Text("line \(finding.line)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    model.reveal(finding)
                } label: {
                    Image(systemName: "arrow.right.circle")
                }
                .buttonStyle(.plain)
                .help("Show in Finder")
            }
            Text(finding.description)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(finding.preview)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.tertiary)
                .lineLimit(1)
        }
        .padding(.vertical, 3)
        .contextMenu {
            Button("Show in Finder") { model.reveal(finding) }
            if let guide = finding.rotation_guide, let url = URL(string: guide) {
                Button("How to rotate this key…") { NSWorkspace.shared.open(url) }
            }
            Button("Copy Path") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(finding.path, forType: .string)
            }
        }
    }

    private var shortPath: String {
        guard let folder = model.folders.first(where: { finding.path.hasPrefix($0.url.path + "/") }) else {
            return finding.path
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
