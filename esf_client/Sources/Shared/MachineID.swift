// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
import Foundation
import CryptoKit
import IOKit

/// A stable hardware binding, never a hostname or user-controlled preference.
public enum MachineID {
    public static func get() throws -> String {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != 0 else { throw LeaseError.machineUnavailable }
        defer { IOObjectRelease(service) }
        guard let value = IORegistryEntryCreateCFProperty(service, kIOPlatformUUIDKey as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String else {
            throw LeaseError.machineUnavailable
        }
        let identity = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard identity.count == 36, identity.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) || $0 == 45 }) else {
            throw LeaseError.machineUnavailable
        }
        return SHA256.hash(data: Data(("hedgehog-machine-v1\0macos\0" + identity).utf8))
            .map { String(format: "%02x", $0) }.joined()
    }
}
