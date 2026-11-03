// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Tests for how the Scanner app turns the CLI's JSON report into the
// green all-clear or the amber "finished with gaps" state.

import XCTest
@testable import HedgehogScanner

final class CoverageStateTests: XCTestCase {
    private func decode(_ json: String) throws -> ScanReport {
        try JSONDecoder().decode(ScanReport.self, from: Data(json.utf8))
    }

    private func coverageJSON(
        complete: Bool,
        filesScanned: Int = 3,
        extra: String = ""
    ) -> String {
        """
        {
          "complete": \(complete),
          "interrupted": false,
          "files_scanned": \(filesScanned),
          "files_skipped_by_type": 0,
          "skipped_types": [],
          "dirs_skipped_by_rule": 0,
          "skipped_dirs": [],
          "files_unreadable": 0,
          "permission_denied": 0,
          "other_read_errors": 0,
          "unreadable_examples": [],
          "files_over_size_limit": 0,
          "size_limit_bytes": 1048576,
          "oversize_examples": [],
          "dirs_beyond_depth_limit": 0,
          "files_skipped_other": 0,
          "other_skip_examples": [],
          "limit_reached": null,
          "images_seen": 0,
          "images_content_not_checked": 0,
          "image_ocr_cap_reached": false
          \(extra)
        }
        """
    }

    private func report(findings: String = "[]", total: Int = 0, interrupted: Bool = false, coverage: String?) -> String {
        var body = """
        "findings": \(findings), "total": \(total), "files_scanned": 3, "elapsed_secs": 1, "interrupted": \(interrupted)
        """
        if let coverage { body += ", \"complete\": false, \"coverage\": \(coverage)" }
        return "{ \(body) }"
    }

    // MARK: Decoding

    func testReportWithoutCoverageStillDecodes() throws {
        // A helper from before coverage existed never sent the field.
        let decoded = try decode(report(coverage: nil))
        XCTAssertNil(decoded.coverage)
        XCTAssertEqual(decoded.total, 0)
    }

    func testReportWithCoverageDecodesEveryField() throws {
        let decoded = try decode(report(coverage: coverageJSON(complete: true)))
        let coverage = try XCTUnwrap(decoded.coverage)
        XCTAssertTrue(coverage.complete)
        XCTAssertEqual(coverage.files_scanned, 3)
        XCTAssertEqual(coverage.size_limit_bytes, 1_048_576)
        XCTAssertNil(coverage.limit_reached)
    }

    // MARK: Coverage state

    func testCompleteCoverageIsAllClear() throws {
        let decoded = try decode(report(coverage: coverageJSON(complete: true, filesScanned: 12)))
        XCTAssertEqual(decoded.coverageState, .allClear(filesChecked: 12))
    }

    func testMissingCoverageIsNeverAllClear() throws {
        let decoded = try decode(report(coverage: nil))
        guard case .gaps(let headline, let reasons) = decoded.coverageState else {
            return XCTFail("a report without coverage must not show green")
        }
        XCTAssertTrue(headline.contains("3 files were checked"), headline)
        XCTAssertEqual(reasons.count, 1)
        XCTAssertTrue(reasons[0].contains("older scanner helper"), reasons[0])
    }

    func testCompleteFlagIsOverriddenByInterruption() throws {
        let decoded = try decode(report(interrupted: true, coverage: coverageJSON(complete: true)))
        guard case .gaps(_, let reasons) = decoded.coverageState else {
            return XCTFail("an interrupted scan must not show green")
        }
        XCTAssertTrue(reasons.contains { $0.contains("stopped before it finished") }, "\(reasons)")
    }

    func testGapStateListsEveryReasonInPlainEnglish() throws {
        let json = """
        {
          "complete": false,
          "interrupted": false,
          "files_scanned": 40,
          "files_skipped_by_type": 7,
          "skipped_types": [{"name": "pdf", "count": 5}, {"name": "zip", "count": 2}],
          "dirs_skipped_by_rule": 3,
          "skipped_dirs": [{"name": "node_modules", "count": 2}, {"name": ".git", "count": 1}],
          "files_unreadable": 2,
          "permission_denied": 1,
          "other_read_errors": 1,
          "unreadable_examples": [
            {"path": "/Users/me/Documents/locked.txt", "reason": "permission denied"},
            {"path": "/Users/me/Documents/gone.txt", "reason": "vanished during the scan"}
          ],
          "files_over_size_limit": 1,
          "size_limit_bytes": 1048576,
          "oversize_examples": ["/Users/me/Documents/huge.log"],
          "dirs_beyond_depth_limit": 1,
          "files_skipped_other": 1,
          "other_skip_examples": ["/Users/me/Documents/pipe (not a regular file)"],
          "limit_reached": "more than 20000 entries",
          "images_seen": 9,
          "images_content_not_checked": 9,
          "image_ocr_cap_reached": false
        }
        """
        let decoded = try decode(report(coverage: json))
        guard case .gaps(let headline, let reasons) = decoded.coverageState else {
            return XCTFail("expected gaps")
        }
        // 7 + 2 + 1 + 1 + 9 = 20 files not checked
        XCTAssertEqual(headline, "40 files were checked. 20 files were not checked.")
        let joined = reasons.joined(separator: "\n")
        XCTAssertTrue(joined.contains("1 file could not be read because macOS denied access: locked.txt"), joined)
        XCTAssertTrue(joined.contains("1 file or folder could not be read: gone.txt"), joined)
        XCTAssertTrue(joined.contains("1 file is larger than the 1 MB limit and was not read: huge.log"), joined)
        XCTAssertTrue(joined.contains("7 files are of a type this scanner cannot read"), joined)
        XCTAssertTrue(joined.contains("(pdf ×5, zip ×2)"), joined)
        XCTAssertTrue(joined.contains("9 images were checked by file name only"), joined)
        XCTAssertTrue(joined.contains("3 folders were skipped because they hold app or developer files (node_modules ×2, .git)"), joined)
        XCTAssertTrue(joined.contains("1 folder is nested too deeply"), joined)
        XCTAssertTrue(joined.contains("1 item was skipped because it is not an ordinary file"), joined)
        XCTAssertTrue(joined.contains("The scan stopped early: more than 20000 entries."), joined)
        XCTAssertFalse(joined.contains("stopped before it finished"), joined)
        // Nothing technical leaks into the wording.
        XCTAssertFalse(joined.contains("/Users/me"), "full paths are not shown: \(joined)")
    }

    func testOnlySkippedFoldersGetsFolderHeadline() throws {
        let json = coverageJSON(complete: false, filesScanned: 5)
            .replacingOccurrences(of: "\"dirs_skipped_by_rule\": 0,", with: "\"dirs_skipped_by_rule\": 2,")
            .replacingOccurrences(of: "\"skipped_dirs\": [],", with: "\"skipped_dirs\": [{\"name\": \"node_modules\", \"count\": 2}],")
        let decoded = try decode(report(coverage: json))
        guard case .gaps(let headline, let reasons) = decoded.coverageState else {
            return XCTFail("expected gaps")
        }
        XCTAssertEqual(headline, "5 files were checked, but some folders were skipped.")
        XCTAssertEqual(reasons.count, 1)
        XCTAssertTrue(reasons[0].hasPrefix("2 folders were skipped"), reasons[0])
    }

    func testFindingsWithGapsIsStillGapState() throws {
        let finding = """
        [{"path": "/x/a.txt", "category": "API Keys", "severity": "critical", "confidence": "definitive",
          "context": "code", "line": 1, "preview": "AKIA****", "description": "AWS Access Key"}]
        """
        let json = coverageJSON(complete: false, filesScanned: 2)
            .replacingOccurrences(of: "\"permission_denied\": 0,", with: "\"permission_denied\": 1,")
            .replacingOccurrences(of: "\"files_unreadable\": 0,", with: "\"files_unreadable\": 1,")
        let decoded = try decode(report(findings: finding, total: 1, coverage: json))
        XCTAssertEqual(decoded.findings.count, 1)
        guard case .gaps(let headline, _) = decoded.coverageState else {
            return XCTFail("expected gaps")
        }
        XCTAssertEqual(headline, "2 files were checked. 1 file was not checked.")
    }

    func testUnreadableFileTypesAreNotesUnderGreenNotGaps() throws {
        let coverage = coverageJSON(complete: false, filesScanned: 7,
                                    extra: ", \"has_gaps\": false").replacingOccurrences(of: "\"files_skipped_by_type\": 0", with: "\"files_skipped_by_type\": 2")
        let decoded = try decode(report(coverage: coverage))
        XCTAssertEqual(decoded.coverageState, .allClear(filesChecked: 7))
        XCTAssertEqual(decoded.coverageNotes.count, 1)
        XCTAssertTrue(decoded.coverageNotes[0].contains("2 files"))
    }

    func testHasGapsTrueIsAmberEvenWhenOnlyFoldersWereSkipped() throws {
        let coverage = coverageJSON(complete: false, extra: ", \"has_gaps\": true").replacingOccurrences(of: "\"dirs_skipped_by_rule\": 0", with: "\"dirs_skipped_by_rule\": 1")
        let decoded = try decode(report(coverage: coverage))
        guard case .gaps = decoded.coverageState else { return XCTFail("expected gaps") }
    }
}
