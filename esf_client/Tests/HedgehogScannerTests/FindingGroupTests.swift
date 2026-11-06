// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Tests for splitting Deep Scan findings into credentials and sensitive
// content, the counts in the header, and the Apple Notes access banner.

import XCTest
@testable import HedgehogScanner

final class FindingGroupTests: XCTestCase {
    private func finding(_ name: String, severity: String = "high", group: String? = nil) throws -> ScanFinding {
        let groupField = group.map { #","group":"\#($0)""# } ?? ""
        let json = #"{"path":"/tmp/\#(name)","category":"X","severity":"\#(severity)","confidence":"high","line":1,"preview":"ab****","description":"Something"\#(groupField)}"#
        return try JSONDecoder().decode(ScanFinding.self, from: Data(json.utf8))
    }

    // MARK: Decoding

    func testGroupDecodes() throws {
        XCTAssertEqual(try finding("a", group: "sensitive").findingGroup, .sensitive)
        XCTAssertEqual(try finding("a", group: "credential").findingGroup, .credential)
    }

    func testMissingGroupCountsAsCredential() throws {
        let f = try finding("a")
        XCTAssertNil(f.group)
        XCTAssertEqual(f.findingGroup, .credential)
    }

    func testUnknownGroupCountsAsCredential() throws {
        XCTAssertEqual(try finding("a", group: "something-new").findingGroup, .credential)
    }

    func testProgressFindingCarriesGroup() throws {
        let line = #"{"event":"finding","files_scanned":0,"findings":1,"finding":{"path":"AppleNotes:x","category":"Financial","severity":"high","confidence":"high","context":"data","line":0,"preview":"4111****","description":"Card number","likelihood":90,"group":"sensitive"}}"#
        let p = try XCTUnwrap(ScanProgress.parse(line))
        XCTAssertEqual(p.finding?.findingGroup, .sensitive)
    }

    // MARK: Counting

    func testTallySummary() {
        XCTAssertEqual(FindingTally(credentials: 38, sensitive: 12).summary(), "38 credentials · 12 sensitive items")
        XCTAssertEqual(FindingTally(credentials: 1, sensitive: 1).summary(), "1 credential · 1 sensitive item")
        XCTAssertEqual(FindingTally(credentials: 3, sensitive: 0).summary(), "3 credentials")
        XCTAssertEqual(FindingTally(credentials: 0, sensitive: 2).summary(), "2 sensitive items")
        XCTAssertEqual(FindingTally().summary(empty: "Nothing found"), "Nothing found")
    }

    func testTallyCountsEachGroup() throws {
        let list = [try finding("a"), try finding("b", group: "sensitive"), try finding("c", group: "credential")]
        XCTAssertEqual(list.tally, FindingTally(credentials: 2, sensitive: 1))
        XCTAssertEqual(list.tally.total, 3)
    }

    // MARK: Sections

    func testCredentialsComeFirstAndEmptySectionsAreLeftOut() throws {
        let list = [try finding("s", group: "sensitive"), try finding("c")]
        XCTAssertEqual(list.sections(bySeverity: true).map(\.group), [.credential, .sensitive])
        XCTAssertEqual([try finding("s", group: "sensitive")].sections(bySeverity: true).map(\.group), [.sensitive])
        XCTAssertTrue([ScanFinding]().sections(bySeverity: true).isEmpty)
    }

    func testSeverityOrderWithinSectionIsStable() throws {
        let list = [
            try finding("low", severity: "low"),
            try finding("high1", severity: "high"),
            try finding("crit", severity: "critical"),
            try finding("card", severity: "critical", group: "sensitive"),
            try finding("high2", severity: "high"),
            try finding("med", severity: "medium"),
        ]
        let sections = list.sections(bySeverity: true)
        XCTAssertEqual(sections[0].findings.map(\.path), ["/tmp/crit", "/tmp/high1", "/tmp/high2", "/tmp/med", "/tmp/low"])
        XCTAssertEqual(sections[1].findings.map(\.path), ["/tmp/card"])
    }

    func testLiveOrderIsKeptWithoutSeveritySort() throws {
        let list = [try finding("newest", severity: "low"), try finding("older", severity: "critical")]
        XCTAssertEqual(list.sections(bySeverity: false)[0].findings.map(\.path), ["/tmp/newest", "/tmp/older"])
    }

    // MARK: Apple Notes banner

    private func report(coverageExtra: String) throws -> ScanReport {
        let json = """
        {"findings": [], "total": 0, "files_scanned": 4, "elapsed_secs": 1, "interrupted": false,
         "coverage": {"complete": true, "has_gaps": false, "interrupted": false, "files_scanned": 4,
          "files_skipped_by_type": 0, "skipped_types": [], "dirs_skipped_by_rule": 0, "skipped_dirs": [],
          "files_unreadable": 0, "permission_denied": 0, "other_read_errors": 0, "unreadable_examples": [],
          "files_over_size_limit": 0, "size_limit_bytes": 1048576, "oversize_examples": [],
          "dirs_beyond_depth_limit": 0, "files_skipped_other": 0, "limit_reached": null,
          "images_seen": 0, "images_content_not_checked": 0, "image_ocr_cap_reached": false\(coverageExtra)}}
        """
        return try JSONDecoder().decode(ScanReport.self, from: Data(json.utf8))
    }

    func testNoBannerWhenFieldIsAbsent() throws {
        let r = try report(coverageExtra: "")
        XCTAssertFalse(r.notesUnreadable)
        XCTAssertEqual(r.coverageState, .allClear(filesChecked: 4))
    }

    func testNoBannerWhenNotesWereRead() throws {
        XCTAssertFalse(try report(coverageExtra: #", "notes_unreadable": false"#).notesUnreadable)
    }

    func testBannerAndGapWhenNotesUnreadable() throws {
        let r = try report(coverageExtra: #", "notes_unreadable": true"#)
        XCTAssertTrue(r.notesUnreadable)
        guard case .gaps(let headline, let reasons) = r.coverageState else {
            return XCTFail("unread notes must not show the green all-clear")
        }
        XCTAssertEqual(headline, "4 files were checked, but Apple Notes could not be read.")
        XCTAssertTrue(reasons.contains { $0.contains("Full Disk Access") }, "\(reasons)")
    }

    func testNoBannerWithoutCoverage() throws {
        let json = #"{"findings": [], "total": 0, "files_scanned": 1, "elapsed_secs": 1, "interrupted": false}"#
        XCTAssertFalse(try JSONDecoder().decode(ScanReport.self, from: Data(json.utf8)).notesUnreadable)
    }

    func testMergedCoverageKeepsNotesUnreadable() throws {
        let unread = try XCTUnwrap(try report(coverageExtra: #", "notes_unreadable": true"#).coverage)
        let plain = try XCTUnwrap(try report(coverageExtra: "").coverage)
        XCTAssertEqual(plain.merging(unread).notes_unreadable, true)
        XCTAssertNil(plain.merging(plain).notes_unreadable)
    }

    func testFullDiskAccessSettingsURL() {
        XCTAssertEqual(ScannerModel.fullDiskAccessSettings.absoluteString,
                       "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
    }

    // MARK: Progress step wording

    func testStepDescriptionDoesNotRepeatThePicturesCount() {
        XCTAssertNil(ScannerModel.stepDescription("images", imagesKnown: true))
        XCTAssertEqual(ScannerModel.stepDescription("images", imagesKnown: false), "Reading the text inside pictures…")
        XCTAssertEqual(ScannerModel.stepDescription("notes", imagesKnown: false), "Reading Apple Notes…")
        XCTAssertNil(ScannerModel.stepDescription(nil, imagesKnown: false))
    }
}
