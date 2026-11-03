// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Which plan this computer is on, read from the bundled CLI's licence
// state, and the two ways to change it: enter a key, or go and buy one.
// The key is passed to the CLI on stdin and never kept by the app.

#if HEDGEHOG_DESKTOP
import AppKit
import Foundation
import SwiftUI

struct LicenseStatus: Codable {
    let state: String?
    let tier: String?
    let email: String?
    let expires_at: String?
    let message: String?
}

private struct ActivateResponse: Codable {
    let error: String?
    let license: LicenseStatus?
}

@MainActor
final class LicenseModel: ObservableObject {
    @Published private(set) var tier: String = "free"
    @Published private(set) var email: String?
    @Published private(set) var state: String = "missing"
    @Published private(set) var isBusy = false
    @Published var errorMessage: String?

    static let pricingURL = URL(string: "https://www.gorse.is/pricing")!
    static let dashboardURL = URL(string: "https://www.gorse.is/dashboard")!

    var isPaid: Bool { tier == "pro" || tier == "team" }
    var tierLabel: String {
        switch tier {
        case "pro": return "Pro"
        case "team": return "Team"
        default: return "Free"
        }
    }

    func refresh() async {
        guard let helper = try? ScanRunner.helperURL() else { return }
        guard let (stdout, _, status) = try? await ScanRunner.execute(helper, arguments: ["license", "status", "--json"], timeout: 20),
              case .exited = status,
              let parsed = try? JSONDecoder().decode(LicenseStatus.self, from: stdout) else { return }
        apply(parsed)
    }

    /// Activates a key typed by the user. The CLI validates it, talks to
    /// gorse.is, and stores the lease; the app only relays the outcome.
    func activate(key: String) async {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !isBusy else { return }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }
        do {
            let helper = try ScanRunner.helperURL()
            let (stdout, stderr, status) = try await ScanRunner.execute(helper, arguments: ["activate", "--stdin", "--json"], timeout: 60, input: Data((trimmed + "\n").utf8))
            if case .timedOut = status { errorMessage = "Activation timed out. Check your connection and try again."; return }
            if let response = try? JSONDecoder().decode(ActivateResponse.self, from: stdout) {
                if let error = response.error, !error.isEmpty { errorMessage = error }
                if let license = response.license { apply(license) }
                if response.error == nil, response.license == nil, let plain = try? JSONDecoder().decode(LicenseStatus.self, from: stdout) { apply(plain) }
            } else if let plain = try? JSONDecoder().decode(LicenseStatus.self, from: stdout) {
                apply(plain)
            } else {
                let detail = String(decoding: stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                errorMessage = detail.isEmpty ? "The key could not be activated." : String(detail.suffix(400))
            }
            if errorMessage == nil && !isPaid { errorMessage = "The key was accepted but no paid plan is active. Check your dashboard at gorse.is." }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func deactivate() async {
        guard let helper = try? ScanRunner.helperURL() else { return }
        _ = try? await ScanRunner.execute(helper, arguments: ["deactivate", "--json"], timeout: 30)
        await refresh()
    }

    private func apply(_ status: LicenseStatus) {
        tier = (status.tier ?? "free").lowercased()
        email = status.email
        state = status.state ?? "missing"
    }

    func openPricing() { NSWorkspace.shared.open(Self.pricingURL) }
    func openDashboard() { NSWorkspace.shared.open(Self.dashboardURL) }
}

/// The plan badge for the toolbar: "Free · Upgrade" or "Pro · name@…".
struct LicenseBadge: View {
    @ObservedObject var model: LicenseModel
    @State private var showingKey = false
    @State private var key = ""

    var body: some View {
        HStack(spacing: 8) {
            Text(model.tierLabel)
                .font(.caption.weight(.bold))
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(model.isPaid ? Color.green.opacity(0.18) : Color.gray.opacity(0.18))
                .foregroundStyle(model.isPaid ? Color.green : Color.secondary)
                .cornerRadius(4)
                .help(model.isPaid ? "This computer is on Gorse \(model.tierLabel)." : "This computer is on the free plan. Pro adds Verify, the stamped report and the whole-home scan.")
            if model.isPaid {
                if let email = model.email, !email.isEmpty {
                    Text(email).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Button("Manage…") { model.openDashboard() }.controlSize(.small)
            } else {
                Button("Upgrade to Pro") { model.openPricing() }.controlSize(.small)
                Button("Enter Key…") { showingKey = true }.controlSize(.small)
            }
        }
        .sheet(isPresented: $showingKey) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Enter your licence key").font(.headline)
                Text("Your key is in your dashboard at gorse.is after purchase. It is sent to gorse.is to bind a lease to this computer and is not kept by this app.")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: 380)
                SecureField("Licence key", text: $key)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 380)
                if let message = model.errorMessage {
                    Text(message).font(.caption).foregroundStyle(.red).frame(maxWidth: 380)
                }
                HStack {
                    Button("Get a key…") { model.openPricing() }
                    Spacer()
                    Button("Cancel") { showingKey = false; model.errorMessage = nil }
                    Button(model.isBusy ? "Activating…" : "Activate") {
                        Task {
                            await model.activate(key: key)
                            if model.isPaid { key = ""; showingKey = false }
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(key.trimmingCharacters(in: .whitespaces).isEmpty || model.isBusy)
                }
            }
            .padding(20)
        }
    }
}
#endif
