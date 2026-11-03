// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Is there a newer Gorse? Asks the bundled CLI (`version --check --json`),
// which makes one request to gorse.is carrying only its version, and shows
// a banner with a download link when the answer is yes. The CLI only reports
// `newer_available` once the release's signature verified; when a newer
// version is published but could not be verified, the banner says so and
// does not offer the download. Desktop build only.

#if HEDGEHOG_DESKTOP
import AppKit
import Foundation
import SwiftUI

private struct VersionCheck: Codable {
    let version: String?
    let latest: String?
    let newer_available: Bool?
    let download_url: String?
    /// "verified" | "missing" | "invalid" | "unbound" | "unreachable" |
    /// "mismatch"; absent on an older CLI, which is never offered as verified.
    let signature: String?
    /// Asset name to hex digest, present when the signature verified.
    let sha256: [String: String]?
}

@MainActor
final class UpdateModel: ObservableObject {
    static let securityURL = URL(string: "https://www.gorse.is/trust")!

    /// A newer, signature-verified release the user should download.
    @Published private(set) var newerVersion: String?
    /// True when the CLI said the release signature verified.
    @Published private(set) var signatureVerified = false
    /// A newer version is published but its signature did not verify
    /// (missing, invalid or unreachable), so it is not offered.
    @Published private(set) var unverifiedVersion: String?
    @Published private(set) var downloadURL = URL(string: "https://www.gorse.is/download")!
    @Published var dismissed = false

    func check() async {
        guard let helper = try? ScanRunner.helperURL() else { return }
        guard let (stdout, _, status) = try? await ScanRunner.execute(helper, arguments: ["version", "--check", "--json"], timeout: 15),
              case .exited(let code) = status, code == 0,
              let parsed = try? JSONDecoder().decode(VersionCheck.self, from: stdout) else { return }
        let verified = parsed.signature == "verified"
        let current = parsed.version ?? HedgehogDesktopApp.version
        // A release is offered only when the CLI says it is newer *and* its
        // signature verified. `newer_available` alone is not enough: an
        // older or misbehaving CLI must not be able to put a Download button
        // in front of an unverified build.
        if parsed.newer_available == true, verified, let latest = parsed.latest, !latest.isEmpty {
            newerVersion = latest
            signatureVerified = true
            unverifiedVersion = nil
            if let url = parsed.download_url.flatMap(URL.init(string:)) { downloadURL = url }
            return
        }
        newerVersion = nil
        signatureVerified = false
        // A newer version that is published but not verified (missing,
        // invalid, unbound, unreachable, mismatch, or no signature field at
        // all) gets the calm notice and no download.
        if let latest = parsed.latest, !latest.isEmpty,
           parsed.newer_available == true || (parsed.signature != nil && Self.isNewer(latest, than: current)) {
            unverifiedVersion = latest
        } else {
            unverifiedVersion = nil
        }
    }

    func openDownload() { NSWorkspace.shared.open(downloadURL) }
    func openSecurity() { NSWorkspace.shared.open(Self.securityURL) }

    /// Numeric dotted comparison; a leading "v" and any pre-release or build
    /// suffix ("-alpha", "+3") are ignored. Unparseable input is never newer.
    static func isNewer(_ candidate: String, than current: String) -> Bool {
        func parts(_ text: String) -> [Int]? {
            var core = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if core.hasPrefix("v") || core.hasPrefix("V") { core.removeFirst() }
            if let cut = core.firstIndex(where: { $0 == "-" || $0 == "+" }) { core = String(core[..<cut]) }
            let numbers = core.split(separator: ".", omittingEmptySubsequences: false).map { Int($0) }
            guard !numbers.isEmpty, numbers.allSatisfy({ $0 != nil }) else { return nil }
            return numbers.compactMap { $0 }
        }
        guard let a = parts(candidate), let b = parts(current) else { return false }
        let width = max(a.count, b.count)
        for index in 0..<width {
            let x = index < a.count ? a[index] : 0
            let y = index < b.count ? b[index] : 0
            if x != y { return x > y }
        }
        return false
    }
}

/// A slim strip under the toolbar when a newer version exists.
struct UpdateBanner: View {
    @ObservedObject var model: UpdateModel

    var body: some View {
        if model.dismissed {
            EmptyView()
        } else if let latest = model.newerVersion, model.signatureVerified {
            HStack(spacing: 10) {
                Image(systemName: "arrow.down.circle.fill").foregroundStyle(.blue)
                Text("Gorse \(latest) is available.").font(.callout)
                Label("Signed release", systemImage: "checkmark.seal.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Signed release, signature verified")
                Button("Download") { model.openDownload() }.controlSize(.small)
                Spacer()
                Button { model.dismissed = true } label: { Image(systemName: "xmark") }.buttonStyle(.plain).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(Color.blue.opacity(0.10))
        } else if model.unverifiedVersion != nil {
            HStack(spacing: 10) {
                Image(systemName: "info.circle").foregroundStyle(.secondary)
                Text("A newer version is published but could not be verified, so it is not recommended. See gorse.is/trust.")
                    .font(.callout)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Button("gorse.is/trust") { model.openSecurity() }
                    .buttonStyle(.link)
                    .font(.callout)
                    .accessibilityLabel("Open gorse.is/trust")
                Spacer()
                Button { model.dismissed = true } label: { Image(systemName: "xmark") }.buttonStyle(.plain).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(Color.secondary.opacity(0.08))
        }
    }
}
#endif
