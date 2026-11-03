// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Optional engines: TruffleHog's detectors, added with one click. The CLI
// does the download, the checksum and the install; this just shows the
// offer, the progress and the result. Desktop build only.

#if HEDGEHOG_DESKTOP
import Foundation
import SwiftUI

private struct EngineStatus: Codable {
    struct TruffleHog: Codable {
        let installed: Bool?
        let managed: Bool?
        let path: String?
        let version: String?
        let available_version: String?
        let download_mb: Int?
    }
    let trufflehog: TruffleHog?
}

@MainActor
final class EngineModel: ObservableObject {
    @Published private(set) var truffleInstalled = false
    @Published private(set) var truffleManaged = false
    @Published private(set) var truffleVersion: String?
    @Published private(set) var availableVersion = "3.99.7"
    @Published private(set) var downloadMB = 75
    @Published private(set) var isInstalling = false
    @Published private(set) var received: Int64 = 0
    @Published private(set) var total: Int64?
    @Published var errorMessage: String?

    func refresh() async {
        guard let helper = try? ScanRunner.helperURL() else { return }
        guard let (stdout, _, status) = try? await ScanRunner.execute(helper, arguments: ["engines", "status", "--json"], timeout: 20),
              case .exited(let code) = status, code == 0,
              let parsed = try? JSONDecoder().decode(EngineStatus.self, from: stdout) else { return }
        truffleInstalled = parsed.trufflehog?.installed ?? false
        truffleManaged = parsed.trufflehog?.managed ?? false
        truffleVersion = parsed.trufflehog?.version
        if let v = parsed.trufflehog?.available_version { availableVersion = v }
        if let mb = parsed.trufflehog?.download_mb { downloadMB = mb }
    }

    func install() async {
        guard !isInstalling else { return }
        isInstalling = true
        errorMessage = nil
        received = 0
        total = nil
        defer { isInstalling = false }
        do {
            let helper = try ScanRunner.helperURL()
            let (stdout, stderr, status) = try await ScanRunner.execute(helper, arguments: ["engines", "install", "trufflehog", "--json", "--progress"], timeout: 900, input: nil) { [weak self] line in
                guard let data = line.data(using: .utf8),
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      json["event"] as? String == "download" else { return }
                let got = (json["received"] as? NSNumber)?.int64Value ?? 0
                let all = (json["total"] as? NSNumber)?.int64Value
                Task { @MainActor in self?.received = got; self?.total = all }
            }
            if case .timedOut = status { errorMessage = "The download timed out."; return }
            if let json = try? JSONSerialization.jsonObject(with: stdout) as? [String: Any], let error = json["error"] as? String {
                errorMessage = error
                return
            }
            if case .exited(let code) = status, code != 0 {
                let detail = String(decoding: stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                errorMessage = detail.isEmpty ? "TruffleHog could not be installed." : String(detail.suffix(400))
                return
            }
        } catch {
            errorMessage = error.localizedDescription
            return
        }
        await refresh()
    }

    func remove() async {
        guard let helper = try? ScanRunner.helperURL() else { return }
        _ = try? await ScanRunner.execute(helper, arguments: ["engines", "remove", "trufflehog", "--json"], timeout: 20)
        await refresh()
    }

    var progressText: String {
        let mb = Double(received) / 1_048_576
        if let total, total > 0 {
            return String(format: "%.0f of %.0f MB", mb, Double(total) / 1_048_576)
        }
        return String(format: "%.0f MB", mb)
    }
    var fraction: Double? {
        guard let total, total > 0 else { return nil }
        return min(1, Double(received) / Double(total))
    }
}

/// The offer card in the Deep Scan pane.
struct EngineCard: View {
    @ObservedObject var model: EngineModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if model.truffleInstalled {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    Text(model.truffleManaged
                         ? "TruffleHog \(model.truffleVersion ?? "") is installed. Its \u{2248}800 detectors run with every Deep Scan, verification off."
                         : "TruffleHog found on this Mac. Its detectors run with every Deep Scan, verification off.")
                        .font(.caption2).foregroundStyle(.secondary)
                    if model.truffleManaged {
                        Button("Remove") { Task { await model.remove() } }.buttonStyle(.link).font(.caption2)
                    }
                }
            } else if model.isInstalling {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Downloading TruffleHog… \(model.progressText)").font(.caption2)
                    if let f = model.fraction { ProgressView(value: f) } else { ProgressView() }
                }
            } else {
                Text("Add TruffleHog's \u{2248}800 detectors").font(.caption.weight(.semibold))
                Text("Open source, by Truffle Security. A \(model.downloadMB) MB download from GitHub (about 175 MB on disk), checked against a known checksum and kept in Gorse's own folder. Runs with verification off, so nothing leaves this Mac.")
                    .font(.caption2).foregroundStyle(.secondary)
                Button("Add TruffleHog") { Task { await model.install() } }.controlSize(.small)
                if let message = model.errorMessage {
                    Text(message).font(.caption2).foregroundStyle(.red)
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.06))
        .cornerRadius(8)
    }
}
#endif
