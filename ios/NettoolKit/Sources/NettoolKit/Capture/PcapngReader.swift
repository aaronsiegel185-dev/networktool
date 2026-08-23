import Foundation

/// pcapng - what Wireshark writes by default, so it is what most shared files are.
///
/// Only the blocks that carry packets are interpreted. The format allows far
/// more (name resolution, statistics, custom blocks); anything unrecognised is
/// skipped by its length, which the format guarantees is present.
public enum PcapngReader {
    static let sectionHeader: UInt32 = 0x0a0d0d0a
    static let interfaceDescription: UInt32 = 0x00000001
    static let enhancedPacket: UInt32 = 0x00000006
    static let simplePacket: UInt32 = 0x00000003

    public static func read(bytes: [UInt8], limit: Int = 200_000) throws -> CaptureFile {
        var reader = ByteReader(bytes)
        var packets: [CapturedPacket] = []
        var linkTypes: [LinkType] = []
        var timestampDivisors: [Double] = []
        var big = false
        var snaplen = 0
        var index = 0

        while reader.remaining >= 12 && packets.count < limit {
            let blockType = try reader.u32(bigEndian: big)
            let blockLength = Int(try reader.u32(bigEndian: big))

            if blockType == sectionHeader {
                // The byte-order magic appears inside each section header, and a
                // file may hold several sections written on different machines.
                let wasBig = big
                let order = try reader.u32(bigEndian: true)
                big = (order == 0x1a2b3c4d)
                // This block's length was read before the magic said which way
                // round the section is, so it only needs swapping if the answer
                // turned out to differ from what was assumed.
                let realLength = (wasBig == big)
                    ? blockLength : Int(UInt32(blockLength).byteSwapped)
                _ = try reader.u16(bigEndian: big)     // major
                _ = try reader.u16(bigEndian: big)     // minor
                _ = try reader.u64(bigEndian: big)     // section length, often -1
                // type(4) + length(4) + magic(4) + major(2) + minor(2) + section length(8)
                let consumed = 24
                try reader.skip(max(0, realLength - consumed))
                linkTypes.removeAll()
                timestampDivisors.removeAll()
                continue
            }

            // A block is type(4) + length(4) + body + length(4): the trailing
            // repeat is what lets a reader walk the file backwards, and skipping
            // it is not optional - leave it and every later block is misread.
            guard blockLength >= 12, blockLength - 12 <= reader.remaining else { break }
            var body = ByteReader(try reader.take(blockLength - 12))
            try reader.skip(4)

            switch blockType {
            case interfaceDescription:
                linkTypes.append(LinkType(value: UInt32(try body.u16(bigEndian: big))))
                _ = try body.u16(bigEndian: big)      // reserved
                let declared = Int(try body.u32(bigEndian: big))
                snaplen = max(snaplen, declared)
                timestampDivisors.append(Self.timestampDivisor(options: body, big: big))

            case enhancedPacket:
                let interface = Int(try body.u32(bigEndian: big))
                let high = try body.u32(bigEndian: big)
                let low = try body.u32(bigEndian: big)
                let captured = Int(try body.u32(bigEndian: big))
                let original = Int(try body.u32(bigEndian: big))
                guard captured <= body.remaining else { break }
                let frame = try body.take(captured)
                let ticks = UInt64(high) << 32 | UInt64(low)
                let divisor = interface < timestampDivisors.count
                    ? timestampDivisors[interface] : 1_000_000
                packets.append(CapturedPacket(
                    id: index,
                    timestamp: Date(timeIntervalSince1970: Double(ticks) / divisor),
                    originalLength: max(original, captured),
                    bytes: frame,
                    linkType: interface < linkTypes.count ? linkTypes[interface] : .ethernet))
                index += 1

            case simplePacket:
                let original = Int(try body.u32(bigEndian: big))
                let frame = body.rest()
                packets.append(CapturedPacket(
                    id: index,
                    timestamp: Date(timeIntervalSince1970: 0),
                    originalLength: max(original, frame.count),
                    bytes: frame,
                    linkType: linkTypes.first ?? .ethernet))
                index += 1

            default:
                break                                  // skipped by its length
            }
        }
        return CaptureFile(packets: packets, linkType: linkTypes.first ?? .ethernet,
                           format: "pcapng", snaplen: snaplen)
    }

    /// if_tsresol (option 9) says what a timestamp tick is worth; the default
    /// is microseconds, and the high bit means the value is a power of two.
    private static func timestampDivisor(options: ByteReader, big: Bool) -> Double {
        var reader = options
        while reader.remaining >= 4 {
            guard let code = try? reader.u16(bigEndian: big),
                  let length = try? reader.u16(bigEndian: big),
                  let value = try? reader.take(Int(length)) else { return 1_000_000 }
            let padding = (4 - Int(length) % 4) % 4
            _ = try? reader.skip(padding)
            if code == 0 { break }
            if code == 9, let resolution = value.first {
                if resolution & 0x80 != 0 {
                    return pow(2.0, Double(resolution & 0x7f))
                }
                return pow(10.0, Double(resolution))
            }
        }
        return 1_000_000
    }
}
