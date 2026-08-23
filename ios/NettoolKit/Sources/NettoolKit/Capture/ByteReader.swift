import Foundation

/// A bounds-checked cursor over captured bytes.
///
/// Every decoder in this package reads through one of these. A capture file is
/// attacker-supplied data by definition - it is whatever was on the wire - so a
/// truncated or malformed frame has to end in a thrown error rather than a
/// crash, and that is only reliable if nothing indexes the buffer directly.
public struct ByteReader {
    public enum Failure: Error, LocalizedError {
        case truncated(needed: Int, available: Int)
        case badValue(String)

        public var errorDescription: String? {
            switch self {
            case let .truncated(needed, available):
                return "truncated: needed \(needed) bytes, \(available) left"
            case let .badValue(what):
                return what
            }
        }
    }

    public let bytes: [UInt8]
    public private(set) var offset: Int
    public let end: Int

    public init(_ bytes: [UInt8], from: Int = 0, to: Int? = nil) {
        self.bytes = bytes
        self.offset = from
        self.end = min(to ?? bytes.count, bytes.count)
    }

    public var remaining: Int { max(0, end - offset) }
    public var isAtEnd: Bool { remaining == 0 }

    public mutating func skip(_ count: Int) throws {
        guard count >= 0, remaining >= count else {
            throw Failure.truncated(needed: count, available: remaining)
        }
        offset += count
    }

    public mutating func u8() throws -> UInt8 {
        guard remaining >= 1 else { throw Failure.truncated(needed: 1, available: remaining) }
        defer { offset += 1 }
        return bytes[offset]
    }

    public mutating func u16(bigEndian: Bool = true) throws -> UInt16 {
        let raw = try take(2)
        return bigEndian
            ? UInt16(raw[0]) << 8 | UInt16(raw[1])
            : UInt16(raw[1]) << 8 | UInt16(raw[0])
    }

    public mutating func u32(bigEndian: Bool = true) throws -> UInt32 {
        let raw = try take(4)
        let be = raw.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        return bigEndian ? be : raw.reversed().reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
    }

    public mutating func u64(bigEndian: Bool = true) throws -> UInt64 {
        let raw = try take(8)
        let be = raw.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        return bigEndian ? be : raw.reversed().reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    }

    public mutating func take(_ count: Int) throws -> [UInt8] {
        guard count >= 0, remaining >= count else {
            throw Failure.truncated(needed: count, available: remaining)
        }
        defer { offset += count }
        return Array(bytes[offset..<(offset + count)])
    }

    /// Everything left, without moving the cursor.
    public func rest() -> [UInt8] {
        guard remaining > 0 else { return [] }
        return Array(bytes[offset..<end])
    }

    public mutating func mac() throws -> MACAddress {
        MACAddress(try take(6))
    }

    public mutating func ipv4() throws -> IPAddress {
        IPAddress(v4: try take(4))
    }

    public mutating func ipv6() throws -> IPAddress {
        IPAddress(v6: try take(16))
    }
}
