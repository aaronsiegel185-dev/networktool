import Foundation

/// The radio metadata a monitor-mode capture carries ahead of each frame.
public struct RadiotapHeader: Sendable {
    public var signalDBM: Int?
    public var noiseDBM: Int?
    public var channelMHz: UInt16?
    public var rateMbps: Double?

    public var snr: Int? {
        guard let signalDBM, let noiseDBM else { return nil }
        return signalDBM - noiseDBM
    }
}

public enum Radiotap {
    /// Fields appear in bit order, each aligned to its own size - so the only
    /// way to reach a later field is to walk every earlier one.
    static let fieldSizes: [(size: Int, alignment: Int)] = [
        (8, 8),   // TSFT
        (1, 1),   // flags
        (1, 1),   // rate
        (4, 2),   // channel
        (2, 2),   // FHSS
        (1, 1),   // antenna signal
        (1, 1),   // antenna noise
        (2, 2),   // lock quality
        (2, 2),   // TX attenuation
        (2, 2),   // dB TX attenuation
        (1, 1),   // dBm TX power
        (1, 1),   // antenna
        (1, 1),   // dB antenna signal
        (1, 1),   // dB antenna noise
        (2, 2),   // RX flags
    ]

    public static func parse(_ reader: inout ByteReader) throws -> RadiotapHeader {
        let start = reader.offset
        _ = try reader.u8()                          // version
        _ = try reader.u8()                          // padding
        let length = Int(try reader.u16(bigEndian: false))
        var present: [UInt32] = [try reader.u32(bigEndian: false)]
        // The high bit chains another presence word; a capture from another
        // machine can carry several.
        while present.last.map({ $0 & 0x8000_0000 != 0 }) == true, present.count < 8 {
            present.append(try reader.u32(bigEndian: false))
        }

        var header = RadiotapHeader()
        let first = present[0]
        for (index, field) in fieldSizes.enumerated() {
            guard first & (1 << UInt32(index)) != 0 else { continue }
            let misalignment = (reader.offset - start) % field.alignment
            if misalignment != 0 { try reader.skip(field.alignment - misalignment) }
            guard reader.remaining >= field.size else { break }
            switch index {
            case 2:
                header.rateMbps = Double(try reader.u8()) / 2.0
            case 3:
                header.channelMHz = try reader.u16(bigEndian: false)
                _ = try reader.u16(bigEndian: false)     // channel flags
            case 5:
                header.signalDBM = Int(Int8(bitPattern: try reader.u8()))
            case 6:
                header.noiseDBM = Int(Int8(bitPattern: try reader.u8()))
            default:
                try reader.skip(field.size)
            }
        }
        // Trust the declared length over the walk: vendor extensions we did not
        // model still have to be stepped over exactly.
        let consumed = reader.offset - start
        if length > consumed { try reader.skip(length - consumed) }
        return header
    }
}

/// An 802.11 frame, as far as the app needs it.
public struct Dot11Frame: Sendable {
    public enum Kind: String, Sendable {
        case beacon, probeRequest, probeResponse, authentication, association
        case deauthentication, disassociation, data, control, other
    }

    public var kind: Kind
    public var ssid: String?
    public var transmitter: MACAddress?
    public var receiver: MACAddress?
    public var bssid: MACAddress?
    public var reasonCode: UInt16?
    public var isRetry: Bool
}

extension PacketDecoder {
    static func dot11(_ reader: inout ByteReader, into packet: inout DecodedPacket) throws {
        packet.layers.append("802.11")
        let frameControl = try reader.u16(bigEndian: false)
        let type = UInt8((frameControl >> 2) & 0x03)
        let subtype = UInt8((frameControl >> 4) & 0x0f)
        let flags = UInt8(frameControl >> 8)
        _ = try reader.u16(bigEndian: false)         // duration

        var frame = Dot11Frame(kind: .other, isRetry: flags & 0x08 != 0)
        let address1 = try? reader.mac()
        let address2 = try? reader.mac()
        let address3 = try? reader.mac()
        frame.receiver = address1
        frame.transmitter = address2
        frame.bssid = address3

        switch (type, subtype) {
        case (0, 8): frame.kind = .beacon
        case (0, 4): frame.kind = .probeRequest
        case (0, 5): frame.kind = .probeResponse
        case (0, 11): frame.kind = .authentication
        case (0, 0), (0, 1), (0, 2), (0, 3): frame.kind = .association
        case (0, 12): frame.kind = .deauthentication
        case (0, 10): frame.kind = .disassociation
        case (1, _): frame.kind = .control
        case (2, _): frame.kind = .data
        default: frame.kind = .other
        }

        if frame.kind == .beacon || frame.kind == .probeResponse {
            _ = try? reader.skip(2)                  // sequence control
            _ = try? reader.skip(12)                 // timestamp, interval, capability
            frame.ssid = readSSID(&reader)
        } else if frame.kind == .probeRequest {
            _ = try? reader.skip(2)
            frame.ssid = readSSID(&reader)
        } else if frame.kind == .deauthentication || frame.kind == .disassociation {
            _ = try? reader.skip(2)
            frame.reasonCode = try? reader.u16(bigEndian: false)
        }

        packet.wireless = frame
        packet.protocolName = "802.11 \(frame.kind.rawValue)"
        packet.sourceMAC = frame.transmitter
        packet.destinationMAC = frame.receiver
        packet.source = frame.transmitter?.description ?? ""
        packet.destination = frame.receiver?.description ?? ""

        var parts: [String] = [frame.kind.rawValue]
        if let ssid = frame.ssid {
            parts.append(ssid.isEmpty ? "(broadcast probe)" : "SSID \(ssid)")
        }
        if let reason = frame.reasonCode { parts.append("reason \(reason): \(reasonName(reason))") }
        if frame.isRetry { parts.append("retry") }
        packet.summary = parts.joined(separator: "  ")
    }

    /// The SSID is the first information element, tag 0.
    static func readSSID(_ reader: inout ByteReader) -> String? {
        guard let tag = try? reader.u8(), tag == 0,
              let length = try? reader.u8(),
              let raw = try? reader.take(Int(length)) else { return nil }
        return String(decoding: raw, as: UTF8.self)
    }

    /// The reason codes worth recognising, all of which mean "your client was
    /// pushed off" and are the usual answer to "why did the Wi-Fi drop".
    static func reasonName(_ code: UInt16) -> String {
        switch code {
        case 1: return "unspecified"
        case 2: return "previous authentication no longer valid"
        case 3: return "station is leaving"
        case 4: return "inactivity timeout"
        case 5: return "AP is out of capacity"
        case 7: return "class 3 frame from a non-associated station"
        case 8: return "station left the BSS"
        case 15: return "4-way handshake timeout"
        case 17: return "AP is out of capacity (assoc)"
        case 23: return "802.1X authentication failed"
        default: return "reason \(code)"
        }
    }
}
