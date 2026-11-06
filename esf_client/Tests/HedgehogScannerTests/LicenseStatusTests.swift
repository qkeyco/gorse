// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Tests for how the Mac app reads `gorse license status --json` and what
// `gorse activate ... --json` prints. A licence that decodes as nothing
// shows Free and fails every activation, so decode the CLI's real shape.
// Desktop build only, like the licence UI: run with
// `swift test -Xswiftc -DHEDGEHOG_DESKTOP`.

#if HEDGEHOG_DESKTOP
import XCTest
@testable import HedgehogScanner

final class LicenseStatusTests: XCTestCase {
    // The shape gorse 0.4.15 prints for an active Pro lease (synthetic values).
    private let active = """
    {"state":"active","tier":"pro","machine_id":"synthetic-machine","email":"user@example.com",
     "issued_at":1793927002,"expires_at":1794013402,"seconds_remaining":86353,"grace_days_remaining":null,
     "issuer_public_key":"synthetic","message":"Signed lease is valid for this machine.","protection_tested":false}
    """

    func testActiveProLeaseDecodes() throws {
        let status = try JSONDecoder().decode(LicenseStatus.self, from: Data(active.utf8))
        XCTAssertEqual(status.tier, "pro")
        XCTAssertEqual(status.state, "active")
        XCTAssertEqual(status.email, "user@example.com")
    }

    func testFreeStatusDecodes() throws {
        let json = #"{"state":"missing","tier":"free","expires_at":null,"message":"No licence."}"#
        let status = try JSONDecoder().decode(LicenseStatus.self, from: Data(json.utf8))
        XCTAssertEqual(status.tier, "free")
    }
}
#endif
