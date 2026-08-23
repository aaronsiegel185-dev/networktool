import Foundation

/// What a decoder made of one frame.
///
/// Flat rather than a tree of protocol objects: every view in the app wants the
/// same handful of facts (who, to whom, over what, how big), and a flat record
/// keeps the packet list fast to sort and filter over tens of thousands of rows.
public struct DecodedPacket: Identifiable, Sendable {
    public let id: Int
    public let timestamp: Date
    public let length: Int
    public let capturedLength: Int

    public var layers: [String] = []
    public var protocolName: String = "unknown"
    public var source: String = ""
    public var destination: String = ""
    public var sourceMAC: MACAddress?
    public var destinationMAC: MACAddress?
    public var sourceIP: IPAddress?
    public var destinationIP: IPAddress?
    public var sourcePort: UInt16?
    public var destinationPort: UInt16?
    public var vlan: UInt16?
    public var summary: String = ""

    public var tcp: TCPHeader?
    public var dns: DNSMessage?
    public var arp: ARPMessage?
    public var wireless: Dot11Frame?
    public var radio: RadiotapHeader?

    /// Offset of the transport payload, so Follow Stream need not decode twice.
    public var payloadRange: Range<Int>?

    public init(id: Int, timestamp: Date, length: Int, capturedLength: Int) {
        self.id = id
        self.timestamp = timestamp
        self.length = length
        self.capturedLength = capturedLength
    }

    /// The pair of endpoints, order-independent, for grouping conversations.
    public var conversationKey: String {
        let a = source.isEmpty ? (sourceMAC?.description ?? "?") : source
        let b = destination.isEmpty ? (destinationMAC?.description ?? "?") : destination
        return a < b ? "\(a)|\(b)" : "\(b)|\(a)"
    }

    /// The 5-tuple as a stream key, again order-independent.
    public var streamKey: String? {
        guard let sourceIP, let destinationIP,
              let sourcePort, let destinationPort else { return nil }
        let a = "\(sourceIP):\(sourcePort)"
        let b = "\(destinationIP):\(destinationPort)"
        return a < b ? "\(protocolName)|\(a)|\(b)" : "\(protocolName)|\(b)|\(a)"
    }
}

public struct TCPHeader: Sendable {
    public var sequence: UInt32
    public var acknowledgement: UInt32
    public var flags: UInt8
    public var window: UInt16
    public var payloadLength: Int

    public var isSYN: Bool { flags & 0x02 != 0 }
    public var isACK: Bool { flags & 0x10 != 0 }
    public var isFIN: Bool { flags & 0x01 != 0 }
    public var isRST: Bool { flags & 0x04 != 0 }
    public var isPSH: Bool { flags & 0x08 != 0 }

    public var flagNames: String {
        var names: [String] = []
        if isFIN { names.append("FIN") }
        if isSYN { names.append("SYN") }
        if isRST { names.append("RST") }
        if isPSH { names.append("PSH") }
        if isACK { names.append("ACK") }
        return names.isEmpty ? "-" : names.joined(separator: ",")
    }
}

public struct ARPMessage: Sendable {
    public var isRequest: Bool
    public var senderIP: IPAddress
    public var senderMAC: MACAddress
    public var targetIP: IPAddress
    public var targetMAC: MACAddress
}
