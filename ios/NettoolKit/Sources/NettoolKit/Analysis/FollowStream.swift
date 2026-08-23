import Foundation

/// One side's bytes, reassembled.
public struct StreamSide: Sendable {
    public let label: String
    public let bytes: [UInt8]

    /// Printable text, with anything unprintable shown as a dot - the same
    /// convention every hex dump uses, so binary payloads stay legible as shape.
    public var text: String {
        String(bytes.map { byte in
            (byte >= 0x20 && byte < 0x7f) || byte == 0x0a || byte == 0x0d
                ? Character(UnicodeScalar(byte)) : "."
        })
    }

    public var looksTextual: Bool {
        guard !bytes.isEmpty else { return false }
        let printable = bytes.filter {
            ($0 >= 0x20 && $0 < 0x7f) || $0 == 0x09 || $0 == 0x0a || $0 == 0x0d
        }
        return Double(printable.count) / Double(bytes.count) > 0.85
    }
}

public struct Stream: Sendable {
    public let key: String
    public let clientToServer: StreamSide
    public let serverToClient: StreamSide
    public let packetCount: Int
}

public enum FollowStream {

    /// Reassemble one TCP or UDP stream in capture order.
    ///
    /// Capture order, not sequence order: with a capture taken at one end, they
    /// are the same thing except where there is loss - and where there is loss,
    /// showing what actually arrived in the order it arrived is the more honest
    /// answer than silently repairing it.
    public static func follow(streamKey: String, in packets: [DecodedPacket],
                              bytesFor: (DecodedPacket) -> [UInt8]) -> Stream? {
        let members = packets.filter { $0.streamKey == streamKey }
        guard let first = members.first else { return nil }

        let clientLabel = "\(first.source):\(first.sourcePort.map(String.init) ?? "")"
        let serverLabel = "\(first.destination):\(first.destinationPort.map(String.init) ?? "")"
        var clientBytes: [UInt8] = []
        var serverBytes: [UInt8] = []

        for packet in members {
            let payload = bytesFor(packet)
            guard !payload.isEmpty else { continue }
            if packet.source == first.source && packet.sourcePort == first.sourcePort {
                clientBytes += payload
            } else {
                serverBytes += payload
            }
        }
        return Stream(
            key: streamKey,
            clientToServer: StreamSide(label: clientLabel, bytes: clientBytes),
            serverToClient: StreamSide(label: serverLabel, bytes: serverBytes),
            packetCount: members.count)
    }
}
