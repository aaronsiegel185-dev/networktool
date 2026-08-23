import Foundation

/// A hardware address, kept as bytes so comparisons never depend on formatting.
public struct MACAddress: Hashable, CustomStringConvertible, Sendable {
    public let bytes: [UInt8]

    public init(_ bytes: [UInt8]) {
        self.bytes = Array(bytes.prefix(6))
    }

    public init?(string: String) {
        let parts = string.split(whereSeparator: { $0 == ":" || $0 == "-" })
        guard parts.count == 6 else { return nil }
        var out: [UInt8] = []
        for part in parts {
            guard part.count == 2, let value = UInt8(part, radix: 16) else { return nil }
            out.append(value)
        }
        bytes = out
    }

    public var description: String {
        bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    public var isBroadcast: Bool { bytes.allSatisfy { $0 == 0xff } }

    /// Multicast is the low bit of the first octet - which makes broadcast a
    /// special case of it, so callers usually want both questions.
    public var isMulticast: Bool { (bytes.first ?? 0) & 0x01 == 1 }

    /// Locally administered: the address was assigned by software, so it says
    /// nothing about who made the hardware and should not be looked up.
    public var isLocallyAdministered: Bool { (bytes.first ?? 0) & 0x02 == 2 }

    /// The 24-bit OUI, uppercase and unpunctuated, for a vendor lookup.
    public var oui: String {
        bytes.prefix(3).map { String(format: "%02X", $0) }.joined()
    }
}

/// An IPv4 or IPv6 address.
public struct IPAddress: Hashable, CustomStringConvertible, Sendable {
    public enum Family: Sendable { case v4, v6 }

    public let family: Family
    public let bytes: [UInt8]

    public init(v4 bytes: [UInt8]) {
        self.family = .v4
        self.bytes = Array(bytes.prefix(4))
    }

    public init(v6 bytes: [UInt8]) {
        self.family = .v6
        self.bytes = Array(bytes.prefix(16))
    }

    public var description: String {
        switch family {
        case .v4:
            return bytes.map(String.init).joined(separator: ".")
        case .v6:
            return Self.formatIPv6(bytes)
        }
    }

    public var isMulticast: Bool {
        switch family {
        case .v4: return (bytes.first ?? 0) >= 224 && (bytes.first ?? 0) <= 239
        case .v6: return bytes.first == 0xff
        }
    }

    /// RFC 1918 / RFC 4193, for telling "inside" from "outside" in a summary.
    public var isPrivate: Bool {
        switch family {
        case .v4:
            guard bytes.count == 4 else { return false }
            if bytes[0] == 10 { return true }
            if bytes[0] == 192 && bytes[1] == 168 { return true }
            if bytes[0] == 172 && (16...31).contains(bytes[1]) { return true }
            if bytes[0] == 169 && bytes[1] == 254 { return true }   // link-local
            return false
        case .v6:
            return (bytes.first ?? 0) & 0xfe == 0xfc || (bytes.first == 0xfe && (bytes[1] & 0xc0) == 0x80)
        }
    }

    /// Canonical IPv6 text: the longest run of zero groups collapses to "::".
    static func formatIPv6(_ bytes: [UInt8]) -> String {
        guard bytes.count == 16 else { return "" }
        var groups: [UInt16] = []
        for index in stride(from: 0, to: 16, by: 2) {
            groups.append(UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1]))
        }
        var bestStart = -1, bestLength = 0
        var runStart = -1, runLength = 0
        for (index, group) in groups.enumerated() {
            if group == 0 {
                if runStart < 0 { runStart = index; runLength = 0 }
                runLength += 1
                if runLength > bestLength { bestStart = runStart; bestLength = runLength }
            } else {
                runStart = -1
                runLength = 0
            }
        }
        // A single zero group is written out; "::" is only worth it for a run.
        if bestLength < 2 { bestStart = -1 }
        var parts: [String] = []
        var index = 0
        while index < groups.count {
            if index == bestStart {
                parts.append("")
                if index == 0 { parts.append("") }
                index += bestLength
                if index >= groups.count { parts.append("") }
                continue
            }
            parts.append(String(groups[index], radix: 16))
            index += 1
        }
        return parts.joined(separator: ":")
    }
}
