// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
import Foundation
import CryptoKit
import Darwin

public enum LicenseTier: Int32 { case free = 0, personal = 1, developer = 2, team = 3 }

public struct VerifiedLease {
    public let tier: LicenseTier
    public let email: String
    public let machineID: String
    public let issuedAt: Date
    public let expiresAt: Date
    /// True once the signed expiry has passed and the lease is inside the
    /// renewal grace: the tier stays effective, renewal is overdue.
    public let inGrace: Bool
    /// When the renewal grace ends and the tier stops being effective.
    public var graceEndsAt: Date { expiresAt.addingTimeInterval(TimeInterval(LeaseVerifier.renewalGraceSeconds)) }
}

public enum LeaseError: Error { case malformed, signature, binding, expired, lifetime, machineUnavailable }

public enum LeaseVerifier {
    /// A signed lease lives at most 24 hours (the server never issues longer).
    public static let maxLeaseSeconds: UInt64 = 86400
    /// After the signed expiry the tier stays effective, and renewal is still
    /// accepted, for a fortnight. Mirrors RENEWAL_GRACE_SECONDS in the CLI's
    /// credential_store.rs; the server still refuses a cancelled subscription.
    public static let renewalGraceSeconds: UInt64 = 14 * 86400
    static let issuer = Data([
        0x74,0xf1,0xac,0x9d,0xba,0x10,0x57,0x51,0x2a,0xbb,0x79,0x7c,0x9c,0x8f,0xa6,0xcc,
        0xfc,0xdb,0xb4,0xd2,0x88,0x06,0xb6,0x40,0x2d,0x77,0x00,0x66,0x13,0x76,0xb3,0x53,
    ])
    private struct Payload: Decodable {
        let tier: String
        let email: String
        let machine_id: String
        let issued_at: UInt64
        let expires_at: UInt64
    }

    public static func validate(key: String, machineID: String, now: Date = Date()) throws -> VerifiedLease {
        try validate(key: key, machineID: machineID, now: now, issuer: issuer)
    }

    // Internal issuer injection supports synthetic cryptographic tests; the
    // public runtime entry point always uses the embedded production issuer.
    static func validate(key: String, machineID: String, now: Date, issuer: Data) throws -> VerifiedLease {
        guard key.utf8.count <= 8192, key.hasPrefix("HH1-"), !machineID.isEmpty else { throw LeaseError.malformed }
        let encoded = String(key.dropFirst(4))
        guard encoded.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else { throw LeaseError.malformed }
        let normalized = encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard let bytes = Data(base64Encoded: normalized + String(repeating: "=", count: (4-normalized.count%4)%4)), bytes.count > 64 else { throw LeaseError.malformed }
        let payloadBytes = bytes.dropLast(64)
        let signature = bytes.suffix(64)
        let verifying = try Curve25519.Signing.PublicKey(rawRepresentation: issuer)
        guard verifying.isValidSignature(signature, for: payloadBytes) else { throw LeaseError.signature }
        guard let object = try JSONSerialization.jsonObject(with: payloadBytes) as? [String: Any],
              Set(object.keys) == Set(["tier","email","machine_id","issued_at","expires_at"]) else { throw LeaseError.malformed }
        let payload = try JSONDecoder().decode(Payload.self, from: payloadBytes)
        let tier: LicenseTier
        switch payload.tier {
        case "personal": tier = .personal
        case "developer": tier = .developer
        case "team": tier = .team
        default: throw LeaseError.malformed
        }
        guard payload.machine_id == machineID else { throw LeaseError.binding }
        guard !payload.email.isEmpty, payload.email.utf8.count <= 254, payload.email.contains("@"),
              !payload.email.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw LeaseError.malformed }
        let timestamp = now.timeIntervalSince1970
        guard timestamp.isFinite, timestamp > 0, timestamp < Double(UInt64.max-5), payload.issued_at > 0,
              payload.issued_at <= UInt64(timestamp)+5,
              payload.expires_at > payload.issued_at, payload.expires_at-payload.issued_at <= maxLeaseSeconds else { throw LeaseError.lifetime }
        // The signed expiry starts the renewal grace rather than ending the
        // entitlement; only the end of the grace does that.
        guard Double(payload.expires_at) + Double(renewalGraceSeconds) > timestamp else { throw LeaseError.expired }
        return VerifiedLease(tier: tier, email: payload.email, machineID: machineID,
                             issuedAt: Date(timeIntervalSince1970: Double(payload.issued_at)),
                             expiresAt: Date(timeIntervalSince1970: Double(payload.expires_at)),
                             inGrace: Double(payload.expires_at) <= timestamp)
    }
}

/// Reads only the named user's private lease. There is no global best tier and
/// no cached grant that can survive expiry, removal or a changed file.
public enum LicenseManager {
    public static func lease(forUID uid: uid_t, now: Date = Date()) -> VerifiedLease? {
        var record = passwd()
        var found: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 32768)
        guard getpwuid_r(uid, &record, &buffer, buffer.count, &found) == 0, found != nil,
              let home = record.pw_dir, let machine = try? MachineID.get() else { return nil }
        return readLease(atHome: String(cString: home), owner: uid, machineID: machine, now: now)
    }

    static func readLease(atHome home: String, owner: uid_t, machineID: String, now: Date, issuer: Data = LeaseVerifier.issuer) -> VerifiedLease? {
        guard home.hasPrefix("/"), let parent = openDirectory(home) else { return nil }
        defer { close(parent) }
        let directory = openat(parent, ".hedgehog", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { return nil }
        defer { close(directory) }
        var dirInfo = stat()
        guard fstat(directory, &dirInfo) == 0, dirInfo.st_uid == owner, dirInfo.st_mode & 0o022 == 0 else { return nil }
        let file = openat(directory, "license.key", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | O_NOCTTY)
        guard file >= 0 else { return nil }
        defer { close(file) }
        var before = stat()
        guard fstat(file, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == owner, before.st_nlink == 1, before.st_mode & 0o077 == 0,
              before.st_size >= 0, before.st_size <= 8192 else { return nil }
        var bytes = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while bytes.count <= 8192 {
            let count = Darwin.read(file, &buffer, min(buffer.count, 8193-bytes.count))
            if count == 0 { break }
            if count < 0 { if errno == EINTR { continue }; return nil }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard bytes.count <= 8192, fstat(file, &after) == 0, before.st_size == after.st_size, before.st_nlink == after.st_nlink, before.st_uid == after.st_uid, before.st_mode == after.st_mode,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              let key = String(data: bytes, encoding: .utf8) else { return nil }
        return try? LeaseVerifier.validate(key: key.trimmingCharacters(in: .whitespacesAndNewlines), machineID: machineID, now: now, issuer: issuer)
    }

    private static func openDirectory(_ path: String) -> Int32? {
        var descriptor = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        for component in path.split(separator: "/") {
            guard component != "..", component != "." else { close(descriptor); return nil }
            let next = String(component).withCString { openat(descriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) }
            close(descriptor)
            guard next >= 0 else { return nil }
            descriptor = next
        }
        return descriptor
    }
}
