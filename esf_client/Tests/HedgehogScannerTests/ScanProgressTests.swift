// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
// Tests for the live progress lines `gorse scan --deep --json --progress`
// writes to stderr, which the app turns into the running count, the folder
// being read, and the findings list that fills in during a scan.

import XCTest
@testable import HedgehogScanner

final class ScanProgressTests: XCTestCase {
    func testFindingLineCarriesTheFinding() throws {
        let line = #"{"event":"finding","files_scanned":12,"findings":3,"finding":{"path":"/tmp/p/creds.txt","category":"API Keys","severity":"critical","confidence":"definitive","context":"code","line":1,"preview":"AKIAIOSF****","description":"AWS Access Key"}}"#
        let progress = try XCTUnwrap(ScanProgress.parse(line))
        XCTAssertEqual(progress.filesScanned, 12)
        XCTAssertEqual(progress.findings, 3)
        XCTAssertEqual(progress.finding?.preview, "AKIAIOSF****")
        XCTAssertEqual(progress.finding?.path, "/tmp/p/creds.txt")
    }

    func testProgressLineHasNoFinding() throws {
        let line = #"{"event":"progress","files_scanned":5,"findings":0,"dir":"/tmp/p"}"#
        let progress = try XCTUnwrap(ScanProgress.parse(line))
        XCTAssertNil(progress.finding)
        XCTAssertEqual(progress.currentDir, "/tmp/p")
    }
}

final class ScanProgressEventsTests: XCTestCase {
    func testEstimateLine() throws {
        let p = try XCTUnwrap(ScanProgress.parse(#"{"event":"estimate","files_total":674926,"bytes_total":91590141048}"#))
        XCTAssertEqual(p.filesTotal, 674926)
        XCTAssertEqual(p.bytesTotal, 91590141048)
    }

    func testImagesLine() throws {
        let p = try XCTUnwrap(ScanProgress.parse(#"{"event":"images","done":75,"total":5000}"#))
        XCTAssertEqual(p.imagesDone, 75)
        XCTAssertEqual(p.imagesTotal, 5000)
        XCTAssertEqual(p.phase, "images")
    }

    @MainActor
    func testFolderInsideAnotherIsDetected() {
        let docs = URL(fileURLWithPath: "/Users/someone/Documents")
        XCTAssertTrue(ScannerModel.isInside(URL(fileURLWithPath: "/Users/someone/Documents/GitHub"), docs))
        XCTAssertFalse(ScannerModel.isInside(URL(fileURLWithPath: "/Users/someone/DocumentsOld"), docs))
        XCTAssertFalse(ScannerModel.isInside(docs, docs))
    }
}

final class FindingWordingTests: XCTestCase {
    private func finding(_ description: String, path: String = "/tmp/a.txt", likelihood: String = "89") throws -> ScanFinding {
        let json = #"{"path":"\#(path)","category":"Financial","severity":"high","confidence":"high","line":3,"preview":"4111****","description":"\#(description)","likelihood":\#(likelihood)}"#
        return try JSONDecoder().decode(ScanFinding.self, from: Data(json.utf8))
    }

    func testKindReasonAndLikelihood() throws {
        let f = try finding("Credit card number — passes the Luhn check")
        XCTAssertEqual(f.kind, "Credit card number")
        XCTAssertEqual(f.reason, "passes the Luhn check")
        XCTAssertEqual(f.likelihood, 89)
    }

    func testOlderReportsWithoutLikelihoodStillDecode() throws {
        let json = #"{"path":"/tmp/a","category":"Passwords","severity":"medium","confidence":"context","line":1,"preview":"x****","description":"Password or secret value assigned in plain text"}"#
        let f = try JSONDecoder().decode(ScanFinding.self, from: Data(json.utf8))
        XCTAssertNil(f.likelihood)
        XCTAssertNil(f.reason)
        XCTAssertEqual(f.kind, "Password or secret value assigned in plain text")
    }

    func testAppleNote() throws {
        XCTAssertTrue(try finding("Seed phrase", path: "AppleNotes:x-coredata://1").isAppleNote)
    }
}
