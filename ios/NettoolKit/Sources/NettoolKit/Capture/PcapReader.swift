import Foundation

/// The classic libpcap format - what `nettool capture -w` writes.
public enum PcapReader {
    static let magicMicro: UInt32 = 0xa1b2c3d4
    static let magicNano: UInt32 = 0xa1b23c4d

    public static func read(bytes: [UInt8], limit: Int = 200_000) throws -> CaptureFile {
        var reader = ByteReader(bytes)
        let magic = try reader.u32()

        // The magic number encodes both byte order and timestamp resolution:
        // read big-endian, a file written little-endian comes back byte-swapped.
        let littleEndian: Bool
        let nanoseconds: Bool
        switch magic {
        case magicMicro: littleEndian = false; nanoseconds = false
        case magicNano: littleEndian = false; nanoseconds = true
        case magicMicro.byteSwapped: littleEndian = true; nanoseconds = false
        case magicNano.byteSwapped: littleEndian = true; nanoseconds = true
        default:
            throw ByteReader.Failure.badValue(
                String(format: "not a pcap file (magic 0x%08x)", magic))
        }
        let big = !littleEndian

        _ = try reader.u16(bigEndian: big)          // major
        _ = try reader.u16(bigEndian: big)          // minor
        _ = try reader.u32(bigEndian: big)          // timezone offset, always 0
        _ = try reader.u32(bigEndian: big)          // sigfigs, always 0
        let snaplen = Int(try reader.u32(bigEndian: big))
        let linkType = LinkType(value: try reader.u32(bigEndian: big))

        var packets: [CapturedPacket] = []
        var index = 0
        while reader.remaining >= 16 && packets.count < limit {
            let seconds = try reader.u32(bigEndian: big)
            let fraction = try reader.u32(bigEndian: big)
            let captured = Int(try reader.u32(bigEndian: big))
            let original = Int(try reader.u32(bigEndian: big))
            guard captured >= 0, captured <= reader.remaining else {
                // A record header claiming more than the file holds means the
                // capture was cut off mid-write; keep what was read.
                break
            }
            let frame = try reader.take(captured)
            let subsecond = nanoseconds
                ? Double(fraction) / 1_000_000_000
                : Double(fraction) / 1_000_000
            packets.append(CapturedPacket(
                id: index,
                timestamp: Date(timeIntervalSince1970: Double(seconds) + subsecond),
                originalLength: max(original, captured),
                bytes: frame,
                linkType: linkType))
            index += 1
        }
        return CaptureFile(packets: packets, linkType: linkType,
                           format: nanoseconds ? "pcap (ns)" : "pcap", snaplen: snaplen)
    }
}
