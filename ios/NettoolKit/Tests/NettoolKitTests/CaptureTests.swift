import XCTest
@testable import NettoolKit

/// Files are built in the test rather than checked in, so what each byte means
/// is visible next to the assertion that depends on it.
enum Fixture {

    static func pcap(linkType: UInt32 = 1, littleEndian: Bool = true,
                     frames: [[UInt8]]) -> Data {
        var bytes: [UInt8] = []
        func put32(_ value: UInt32) {
            bytes += littleEndian
                ? [UInt8(value & 0xff), UInt8((value >> 8) & 0xff),
                   UInt8((value >> 16) & 0xff), UInt8((value >> 24) & 0xff)]
                : [UInt8((value >> 24) & 0xff), UInt8((value >> 16) & 0xff),
                   UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
        }
        func put16(_ value: UInt16) {
            bytes += littleEndian
                ? [UInt8(value & 0xff), UInt8(value >> 8)]
                : [UInt8(value >> 8), UInt8(value & 0xff)]
        }
        put32(0xa1b2c3d4)
        put16(2); put16(4)
        put32(0); put32(0)
        put32(65535)
        put32(linkType)
        for (index, frame) in frames.enumerated() {
            put32(UInt32(1_700_000_000 + index))
            put32(UInt32(index * 1000))
            put32(UInt32(frame.count))
            put32(UInt32(frame.count))
            bytes += frame
        }
        return Data(bytes)
    }

    /// An Ethernet frame carrying IPv4 and TCP.
    static func tcpFrame(source: [UInt8] = [192, 168, 1, 10],
                         destination: [UInt8] = [192, 168, 1, 20],
                         sourcePort: UInt16 = 51000, destinationPort: UInt16 = 443,
                         sequence: UInt32 = 1000, flags: UInt8 = 0x18,
                         window: UInt16 = 64240, payload: [UInt8] = []) -> [UInt8] {
        var frame: [UInt8] = []
        frame += [0x3c, 0x22, 0xfb, 0x00, 0x00, 0x02]      // destination MAC
        frame += [0x3c, 0x22, 0xfb, 0x00, 0x00, 0x01]      // source MAC
        frame += [0x08, 0x00]                              // IPv4
        frame += [0x45, 0x00]                              // version/IHL, DSCP
        let total = 20 + 20 + payload.count
        frame += [UInt8(total >> 8), UInt8(total & 0xff)]
        frame += [0, 0, 0x40, 0, 64, 6, 0, 0]              // id, flags, TTL, proto TCP
        frame += source
        frame += destination
        frame += [UInt8(sourcePort >> 8), UInt8(sourcePort & 0xff)]
        frame += [UInt8(destinationPort >> 8), UInt8(destinationPort & 0xff)]
        frame += [UInt8(sequence >> 24), UInt8((sequence >> 16) & 0xff),
                  UInt8((sequence >> 8) & 0xff), UInt8(sequence & 0xff)]
        frame += [0, 0, 0, 0]                              // acknowledgement
        frame += [0x50, flags]                             // offset 5 words, flags
        frame += [UInt8(window >> 8), UInt8(window & 0xff)]
        frame += [0, 0, 0, 0]                              // checksum, urgent
        frame += payload
        return frame
    }

    /// An ARP request, which every LAN capture is full of.
    static func arpFrame() -> [UInt8] {
        var frame: [UInt8] = Array(repeating: 0xff, count: 6)
        frame += [0x3c, 0x22, 0xfb, 0x11, 0x22, 0x33]
        frame += [0x08, 0x06]
        frame += [0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]
        frame += [0x3c, 0x22, 0xfb, 0x11, 0x22, 0x33]
        frame += [192, 168, 1, 42]
        frame += Array(repeating: 0, count: 6)
        frame += [192, 168, 1, 1]
        return frame
    }
}

final class PcapReaderTests: XCTestCase {

    func testReadsALittleEndianFile() throws {
        let data = Fixture.pcap(frames: [Fixture.tcpFrame(), Fixture.arpFrame()])
        let file = try CaptureFile.read(data: data)
        XCTAssertEqual(file.packets.count, 2)
        XCTAssertEqual(file.linkType, .ethernet)
        XCTAssertEqual(file.snaplen, 65535)
    }

    func testReadsABigEndianFile() throws {
        // The magic number is what says which way round the file is, and a
        // capture written on another machine may disagree with this one.
        let data = Fixture.pcap(littleEndian: false, frames: [Fixture.arpFrame()])
        let file = try CaptureFile.read(data: data)
        XCTAssertEqual(file.packets.count, 1)
        XCTAssertEqual(file.packets[0].bytes.count, Fixture.arpFrame().count)
    }

    func testRejectsSomethingThatIsNotACapture() {
        XCTAssertThrowsError(try CaptureFile.read(data: Data("not a pcap at all".utf8)))
    }

    func testATruncatedRecordKeepsWhatWasRead() throws {
        // A capture cut off mid-write is the normal result of Ctrl-C, and the
        // packets before the cut are still worth reading.
        var data = Fixture.pcap(frames: [Fixture.tcpFrame(), Fixture.tcpFrame()])
        data = data.prefix(data.count - 20)
        let file = try CaptureFile.read(data: data)
        XCTAssertEqual(file.packets.count, 1)
    }

    func testAnEmptyCaptureIsNotAnError() throws {
        let file = try CaptureFile.read(data: Fixture.pcap(frames: []))
        XCTAssertTrue(file.packets.isEmpty)
        XCTAssertEqual(file.duration, 0)
    }
}

final class ByteReaderTests: XCTestCase {

    func testItRefusesToReadPastTheEnd() {
        var reader = ByteReader([1, 2, 3])
        XCTAssertNoThrow(try reader.u16())
        XCTAssertThrowsError(try reader.u32())
    }

    func testEndiannessBothWays() throws {
        var reader = ByteReader([0x12, 0x34])
        XCTAssertEqual(try reader.u16(bigEndian: true), 0x1234)
        var other = ByteReader([0x12, 0x34])
        XCTAssertEqual(try other.u16(bigEndian: false), 0x3412)
    }

    func testASubRangeCannotEscapeIt() {
        // Decoders hand each other bounded slices; the bound has to hold.
        var reader = ByteReader([1, 2, 3, 4, 5, 6], from: 2, to: 4)
        XCTAssertEqual(reader.remaining, 2)
        XCTAssertThrowsError(try reader.take(3))
    }
}
