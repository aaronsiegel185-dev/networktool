import XCTest
@testable import NettoolKit

final class DecoderTests: XCTestCase {

    private func decode(_ frames: [[UInt8]], linkType: UInt32 = 1) throws -> [DecodedPacket] {
        let file = try CaptureFile.read(data: Fixture.pcap(linkType: linkType,
                                                           frames: frames))
        return PacketDecoder.decodeAll(file)
    }

    func testTCPOverIPv4() throws {
        let packets = try decode([Fixture.tcpFrame(payload: [1, 2, 3, 4])])
        let packet = packets[0]
        XCTAssertEqual(packet.source, "192.168.1.10")
        XCTAssertEqual(packet.destination, "192.168.1.20")
        XCTAssertEqual(packet.destinationPort, 443)
        XCTAssertEqual(packet.protocolName, "HTTPS")
        XCTAssertEqual(packet.tcp?.payloadLength, 4)
        XCTAssertEqual(packet.tcp?.flagNames, "PSH,ACK")
        XCTAssertEqual(packet.layers, ["Ethernet", "IPv4", "TCP"])
    }

    func testARP() throws {
        let packets = try decode([Fixture.arpFrame()])
        XCTAssertEqual(packets[0].protocolName, "ARP")
        XCTAssertEqual(packets[0].arp?.senderIP.description, "192.168.1.42")
        XCTAssertTrue(packets[0].summary.contains("Who has 192.168.1.1?"))
    }

    func testAVLANTagIsUnwrappedAndKept() throws {
        var frame = Fixture.tcpFrame()
        // Splice a 802.1Q tag in after the MACs, as a trunk port would.
        frame.replaceSubrange(12..<14, with: [0x81, 0x00, 0x00, 0x1e, 0x08, 0x00])
        let packets = try decode([frame])
        XCTAssertEqual(packets[0].vlan, 30)
        XCTAssertEqual(packets[0].destinationPort, 443, "the tag must not shift the payload")
    }

    func testATruncatedFrameIsKeptRatherThanDropped() throws {
        // Snaplen-limited captures end mid-header all the time.
        let frame = Array(Fixture.tcpFrame().prefix(20))
        let packets = try decode([frame])
        XCTAssertEqual(packets.count, 1)
        XCTAssertTrue(packets[0].layers.contains("truncated"))
    }

    func testConversationKeyIsOrderIndependent() throws {
        let there = try decode([Fixture.tcpFrame()])[0]
        let back = try decode([Fixture.tcpFrame(source: [192, 168, 1, 20],
                                                destination: [192, 168, 1, 10],
                                                sourcePort: 443,
                                                destinationPort: 51000)])[0]
        XCTAssertEqual(there.conversationKey, back.conversationKey)
        XCTAssertEqual(there.streamKey, back.streamKey)
    }
}

final class DNSTests: XCTestCase {

    /// A query for www.example.com, hand-assembled.
    private func query() -> [UInt8] {
        var message: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in ["www", "example", "com"] {
            message.append(UInt8(label.count))
            message += Array(label.utf8)
        }
        message += [0, 0, 1, 0, 1]        // root, type A, class IN
        return message
    }

    func testParsesAQuery() throws {
        var reader = ByteReader(query())
        let message = try DNSMessage.parse(&reader)
        XCTAssertFalse(message.isResponse)
        XCTAssertEqual(message.questions.first?.name, "www.example.com")
        XCTAssertEqual(message.questions.first?.typeName, "A")
        XCTAssertEqual(message.summary, "query A www.example.com")
    }

    func testReportsAFailedLookup() throws {
        var bytes = query()
        bytes[2] = 0x81
        bytes[3] = 0x83                   // response, NXDOMAIN
        var reader = ByteReader(bytes)
        let message = try DNSMessage.parse(&reader)
        XCTAssertTrue(message.failed)
        XCTAssertEqual(message.responseCodeName, "NXDOMAIN")
    }

    func testACompressionLoopTerminates() throws {
        // A pointer to itself is the classic malformed-DNS hang; it has to end.
        let bytes: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                              0xc0, 0x0c, 0, 1, 0, 1]
        var reader = ByteReader(bytes)
        XCTAssertNoThrow(try DNSMessage.parse(&reader))
    }
}
