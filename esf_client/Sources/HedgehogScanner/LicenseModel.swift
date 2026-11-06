// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Which plan this computer is on, read from the bundled CLI's licence
// state, and the ways to change it: sign in through the browser, enter a
// key, or go and buy one. Keys and the browser sign-in secret are passed
// to the CLI on stdin and never kept or shown by the app.

#if HEDGEHOG_DESKTOP
import AppKit
import Foundation
import SwiftUI

struct LicenseStatus: Codable {
    let state: String?
    let tier: String?
    let email: String?
    // expires_at is left out on purpose: the CLI sends it as a Unix time
    // (a number), and a String field here made every licence fail to decode.
    let message: String?
}

private struct ActivateResponse: Codable {
    let error: String?
    let license: LicenseStatus?
}

/// What `activate --browser-start --json` prints: a short code for the
/// person to match in the browser, and a secret only the CLI needs back.
private struct BrowserStart: Codable {
    let user_code: String?
    let verify_url: String?
    let device_secret: String?
    let interval: Int?
    let expires_in: Int?
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
    /// The code shown while the person finishes signing in in the browser.
    @Published private(set) var browserCode: String?
    @Published private(set) var isWaitingForBrowser = false
    /// Set when a browser sign-in ends with errorMessage, so the badge can say why.
    @Published var showBrowserError = false

    private var browserURL: URL?
    private var browserTask: Task<Void, Never>?

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
            applyActivation(stdout: stdout, stderr: stderr, fallback: "The key could not be activated.")
            if errorMessage == nil && !isPaid { errorMessage = "The key was accepted but no paid plan is active. Check your dashboard at gorse.is." }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Activates by signing in at gorse.is: the CLI hands back a short code,
    /// the browser opens on it, and the CLI waits until the person approves.
    func activateInBrowser() {
        guard !isBusy, browserTask == nil else { return }
        browserTask = Task { await runBrowserActivation() }
    }

    /// Stops waiting. Cancelling the task terminates the waiting CLI.
    func cancelBrowserActivation() {
        browserTask?.cancel()
        finishBrowserActivation()
    }

    func reopenBrowserPage() {
        if let browserURL { NSWorkspace.shared.open(browserURL) }
    }

    private func runBrowserActivation() async {
        isBusy = true
        errorMessage = nil
        defer {
            if !Task.isCancelled {
                finishBrowserActivation()
                showBrowserError = errorMessage != nil
            }
        }
        do {
            let helper = try ScanRunner.helperURL()
            let (startOut, startErr, startStatus) = try await ScanRunner.execute(helper, arguments: ["activate", "--browser-start", "--json"], timeout: 30)
            if Task.isCancelled { return }
            if case .timedOut = startStatus { errorMessage = "Could not reach gorse.is. Check your connection and try again."; return }
            guard let start = try? JSONDecoder().decode(BrowserStart.self, from: startOut),
                  let code = start.user_code, let secret = start.device_secret,
                  let link = start.verify_url, let url = URL(string: link) else {
                if let failed = try? JSONDecoder().decode(ActivateResponse.self, from: startOut) {
                    if let license = failed.license { apply(license) }
                    errorMessage = failed.error ?? "Could not start sign-in. Try again."
                } else {
                    let detail = String(decoding: startErr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                    errorMessage = detail.isEmpty ? "Could not start sign-in. Try again." : String(detail.suffix(400))
                }
                return
            }
            browserCode = code
            browserURL = url
            isWaitingForBrowser = true
            NSWorkspace.shared.open(url)

            let wait = TimeInterval(start.expires_in ?? 900) + 30
            let (stdout, stderr, status) = try await ScanRunner.execute(helper, arguments: ["activate", "--browser-wait", "--stdin", "--json"], timeout: wait, input: Data((secret + "\n").utf8))
            if Task.isCancelled { return }
            if case .timedOut = status { errorMessage = "The code expired. Start again."; return }
            applyActivation(stdout: stdout, stderr: stderr, fallback: "Activation did not finish. Try again.")
            if errorMessage == nil && !isPaid { errorMessage = "You signed in but no paid plan is active. Check your dashboard at gorse.is." }
        } catch {
            if !Task.isCancelled { errorMessage = error.localizedDescription }
        }
    }

    private func finishBrowserActivation() {
        browserTask = nil
        browserCode = nil
        browserURL = nil
        isWaitingForBrowser = false
        isBusy = false
    }

    /// Reads what `activate ... --json` printed: the licence, or an error
    /// with the licence as it now stands.
    private func applyActivation(stdout: Data, stderr: Data, fallback: String) {
        if let response = try? JSONDecoder().decode(ActivateResponse.self, from: stdout) {
            if let error = response.error, !error.isEmpty { errorMessage = error }
            if let license = response.license { apply(license) }
            if response.error == nil, response.license == nil, let plain = try? JSONDecoder().decode(LicenseStatus.self, from: stdout) { apply(plain) }
        } else if let plain = try? JSONDecoder().decode(LicenseStatus.self, from: stdout) {
            apply(plain)
        } else {
            let detail = String(decoding: stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            errorMessage = detail.isEmpty ? fallback : String(detail.suffix(400))
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
                Button("Activate Pro…") {
                    model.activateInBrowser()
                }
                .controlSize(.small)
                .disabled(model.isBusy)
                .help("Sign in at gorse.is in your browser to turn on Pro for this computer.")
                // Buying and pasting a key are rarer than signing in, so they
                // share one small menu; four buttons did not fit the toolbar.
                Menu {
                    Button("Buy Pro…") { model.openPricing() }
                    Button("Enter Key…") { showingKey = true }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("Buy Pro, or paste a licence key you already have.")
            }
        }
        .fixedSize()
        .sheet(isPresented: Binding(get: { model.isWaitingForBrowser }, set: { if !$0 { model.cancelBrowserActivation() } })) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Finish in your browser").font(.headline)
                Text("Check that your browser shows this code, then click Activate.")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: 380, alignment: .leading)
                Text(model.browserCode ?? "")
                    .font(.system(size: 32, weight: .semibold, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: 380)
                    .padding(.vertical, 6)
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Waiting for you to click Activate…").font(.caption).foregroundStyle(.secondary)
                }
                HStack {
                    Button("Open the page again") { model.reopenBrowserPage() }
                    Spacer()
                    Button("Cancel") { model.cancelBrowserActivation() }
                        .keyboardShortcut(.cancelAction)
                }
            }
            .padding(20)
            .frame(width: 420)
        }
        .alert("Pro was not activated", isPresented: $model.showBrowserError) {
            Button("OK") { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
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
