import Foundation

/// One captured frame, as read from a file.
public struct CapturedPacket: Identifiable, Sendable {
    public let id: Int
    public let timestamp: Date
    public let originalLength: Int
    public let bytes: [UInt8]
    public let linkType: LinkType

    /// True when the capture kept less than the frame carried, so a decoder
    /// running off the end is the file's doing rather than a bug.
    public var isTruncated: Bool { bytes.count < originalLength }

    public init(id: Int, timestamp: Date, originalLength: Int,
                bytes: [UInt8], linkType: LinkType) {
        self.id = id
        self.timestamp = timestamp
        self.originalLength = originalLength
        self.bytes = bytes
        self.linkType = linkType
    }
}

/// The handful of link types a capture from nettool can carry.
public enum LinkType: UInt32, Sendable {
    case ethernet = 1
    case raw = 101
    case ieee802_11 = 105
    case linuxSLL = 113
    case ieee802_11Radiotap = 127
    case unknown = 0xffff

    public init(value: UInt32) {
        self = LinkType(rawValue: value) ?? .unknown
    }

    public var name: String {
        switch self {
        case .ethernet: return "Ethernet"
        case .raw: return "Raw IP"
        case .ieee802_11: return "802.11"
        case .linuxSLL: return "Linux cooked"
        case .ieee802_11Radiotap: return "802.11 + radiotap"
        case .unknown: return "unknown"
        }
    }

    public var isWireless: Bool {
        self == .ieee802_11 || self == .ieee802_11Radiotap
    }
}

/// A parsed capture file.
public struct CaptureFile: Sendable {
    public let packets: [CapturedPacket]
    public let linkType: LinkType
    public let format: String
    public let snaplen: Int

    public var duration: TimeInterval {
        guard let first = packets.first?.timestamp, let last = packets.last?.timestamp
        else { return 0 }
        return last.timeIntervalSince(first)
    }

    public var totalBytes: Int { packets.reduce(0) { $0 + $1.originalLength } }

    /// Read whichever of the two pcap formats this file is.
    ///
    /// The magic number decides, rather than the extension: files arriving from
    /// AirDrop or Files often lose the name they were written with.
    public static func read(data: Data, limit: Int = 200_000) throws -> CaptureFile {
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else {
            throw ByteReader.Failure.badValue("file is too short to be a capture")
        }
        let magic = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16
                  | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
        switch magic {
        case 0x0a0d0d0a:
            return try PcapngReader.read(bytes: bytes, limit: limit)
        default:
            return try PcapReader.read(bytes: bytes, limit: limit)
        }
    }

    public static func read(url: URL, limit: Int = 200_000) throws -> CaptureFile {
        // Files handed over by the document picker live outside the sandbox
        // until this is granted, and stay unreadable without it.
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        return try read(data: Data(contentsOf: url), limit: limit)
    }
}
