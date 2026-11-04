// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Tests for how the Mac app reads `gorse schedule history --json` and the
// last run in `gorse schedule status --json`. An incomplete run must never
// read as "no findings", and a run that does not say how it went must never
// read as a success. Desktop build only, like the schedule UI: run with
// `swift test -Xswiftc -DHEDGEHOG_DESKTOP`.

#if HEDGEHOG_DESKTOP
import XCTest
@testable import HedgehogScanner

final class ScheduleHistoryTests: XCTestCase {
    private struct History: Decodable { let runs: [ScheduleRun] }

    private func decodeRuns(_ json: String) throws -> [ScheduleRun] {
        try JSONDecoder().decode(History.self, from: Data(json.utf8)).runs
    }

    private func decodeRun(_ json: String) throws -> ScheduleRun {
        try JSONDecoder().decode(ScheduleRun.self, from: Data(json.utf8))
    }

    /// The exact shape the audit captured: no `ok`, `incomplete: true`, zero counts.
    func testAuditedIncompleteHistoryEntryIsNotNoFindings() throws {
        let runs = try decodeRuns("""
        {
          "runs": [
            {
              "accepted_by_user": false,
              "at": "2026-11-03T23:20:53Z",
              "counts": { "critical": 0, "high": 0, "low": 0, "medium": 0 },
              "coverage_failures": 1,
              "file": "20261103T232053Z.json",
              "first_run": true,
              "improved": 0,
              "incomplete": true,
              "new": 0,
              "resolved": 0,
              "trigger": "manual",
              "unassessed": 0,
              "worsened": 0
            }
          ],
          "total": 1
        }
        """)
        XCTAssertEqual(runs.count, 1)
        let run = runs[0]
        XCTAssertNil(run.ok)
        XCTAssertEqual(run.incomplete, true)
        XCTAssertEqual(run.coverage_failures, 1)
        XCTAssertEqual(run.unassessed, 0)
        XCTAssertEqual(run.outcome, .incomplete(notRead: 1, notAssessed: 0))
        XCTAssertEqual(run.incompleteSummary, "incomplete: 1 location not read")
    }

    func testIncompleteWinsOverOkAndCounts() throws {
        let run = try decodeRun("""
        {"ok": true, "incomplete": true, "coverage_failures": 3, "unassessed": 2,
         "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0}}
        """)
        XCTAssertEqual(run.outcome, .incomplete(notRead: 3, notAssessed: 2))
        XCTAssertEqual(run.incompleteSummary, "incomplete: 3 locations not read · 2 not assessed")
    }

    func testMissingOkAndIncompleteIsUnknownNotSuccess() throws {
        let run = try decodeRun("""
        {"at": "2026-11-03T23:20:53Z", "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
        """)
        XCTAssertEqual(run.outcome, .unknown)
        XCTAssertNil(run.incompleteSummary)
    }

    func testCompleteHistoryEntryWithoutOkIsClean() throws {
        let run = try decodeRun("""
        {"incomplete": false, "coverage_failures": 0, "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
        """)
        XCTAssertEqual(run.outcome, .clean)
    }

    func testFindingsAreCountedWhenOkIsMissing() throws {
        let run = try decodeRun("""
        {"counts": {"critical": 0, "high": 2, "medium": 1, "low": 0}}
        """)
        XCTAssertEqual(run.outcome, .findings(3))
    }

    func testFailedRunWithoutIncompleteDidNotComplete() throws {
        let run = try decodeRun(#"{"ok": false, "message": "scan crashed"}"#)
        XCTAssertEqual(run.outcome, .failed)
    }

    /// The status `last_run` shape: `ok: false` alongside `incomplete: true`.
    func testStatusLastRunIncompleteReadsIncomplete() throws {
        let run = try decodeRun("""
        {"at": "2026-11-03T23:20:53Z", "ok": false, "incomplete": true, "coverage_failures": 2,
         "unassessed": 0, "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
         "message": "incomplete: 2 locations could not be read"}
        """)
        XCTAssertEqual(run.outcome, .incomplete(notRead: 2, notAssessed: 0))
    }
}
#endif
