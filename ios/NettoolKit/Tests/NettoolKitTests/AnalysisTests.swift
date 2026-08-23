import XCTest
@testable import NettoolKit

final class AnalyzerTests: XCTestCase {

    private func analyze(_ frames: [[UInt8]]) throws -> Analysis {
        let file = try CaptureFile.read(data: Fixture.pcap(frames: frames))
        return Analyzer.analyze(PacketDecoder.decodeAll(file))
    }

    func testCountsAConversationInBothDirections() throws {
        let analysis = try analyze([
            Fixture.tcpFrame(payload: [1, 2, 3]),
            Fixture.tcpFrame(source: [192, 168, 1, 20], destination: [192, 168, 1, 10],
                             sourcePort: 443, destinationPort: 51000),
        ])
        XCTAssertEqual(analysis.conversations.count, 1)
        let conversation = analysis.conversations[0]
        XCTAssertEqual(conversation.packets, 2)
        XCTAssertFalse(conversation.isOneSided)
    }

    func testFlagsAOneSidedConversation() throws {
        let analysis = try analyze(Array(repeating: Fixture.tcpFrame(payload: [1]), count: 3))
        XCTAssertTrue(analysis.conversations[0].isOneSided)
    }

    func testSpotsARetransmission() throws {
        // Same sequence number carrying data twice is the definition.
        let analysis = try analyze([
            Fixture.tcpFrame(sequence: 1000, payload: [1, 2, 3, 4]),
            Fixture.tcpFrame(sequence: 1004, payload: [5, 6, 7, 8]),
            Fixture.tcpFrame(sequence: 1000, payload: [1, 2, 3, 4]),
        ])
        XCTAssertEqual(analysis.retransmissions, 1)
        XCTAssertTrue(analysis.findings.contains { $0.message.contains("retransmission") })
    }

    func testSpotsAZeroWindow() throws {
        let analysis = try analyze([Fixture.tcpFrame(window: 0)])
        XCTAssertEqual(analysis.zeroWindows, 1)
        XCTAssertTrue(analysis.findings.contains { $0.severity == .critical })
    }

    func testSpotsAnUnansweredHandshake() throws {
        // A SYN with no SYN-ACK ever coming back: a firewall, or nothing listening.
        let analysis = try analyze([Fixture.tcpFrame(flags: 0x02)])
        XCTAssertEqual(analysis.failedHandshakes, 1)
    }

    func testACompletedHandshakeIsNotFlagged() throws {
        let analysis = try analyze([
            Fixture.tcpFrame(flags: 0x02),
            Fixture.tcpFrame(source: [192, 168, 1, 20], destination: [192, 168, 1, 10],
                             sourcePort: 443, destinationPort: 51000, flags: 0x12),
        ])
        XCTAssertEqual(analysis.failedHandshakes, 0)
    }

    func testACleanCaptureSaysSo() throws {
        let analysis = try analyze([Fixture.arpFrame()])
        XCTAssertEqual(analysis.findings.first?.severity, .ok)
    }

    func testAnEmptyCaptureDoesNotCrash() {
        let analysis = Analyzer.analyze([])
        XCTAssertEqual(analysis.packetCount, 0)
        XCTAssertTrue(analysis.conversations.isEmpty)
    }
}

final class FilterTests: XCTestCase {

    private func packets() throws -> [DecodedPacket] {
        let file = try CaptureFile.read(data: Fixture.pcap(frames: [
            Fixture.tcpFrame(destinationPort: 443),
            Fixture.tcpFrame(destinationPort: 22),
            Fixture.arpFrame(),
        ]))
        return PacketDecoder.decodeAll(file)
    }

    func testFiltersByPort() throws {
        let filtered = try PacketFilter("port == 443").apply(to: packets())
        XCTAssertEqual(filtered.count, 1)
        XCTAssertEqual(filtered[0].destinationPort, 443)
    }

    func testFiltersByProtocolName() throws {
        XCTAssertEqual(try PacketFilter("arp").apply(to: packets()).count, 1)
    }

    func testNegation() throws {
        XCTAssertEqual(try PacketFilter("not arp").apply(to: packets()).count, 2)
    }

    func testAndCombinesTerms() throws {
        let filtered = try PacketFilter("ip.src == 192.168.1.10 and port == 22")
            .apply(to: packets())
        XCTAssertEqual(filtered.count, 1)
    }

    func testOrCombinesTerms() throws {
        let filtered = try PacketFilter("port == 443 or arp").apply(to: packets())
        XCTAssertEqual(filtered.count, 2)
    }

    func testAnUnknownFieldIsReportedRatherThanIgnored() {
        // Silently matching everything would look like a capture with no filter,
        // which is the one outcome that hides the mistake.
        XCTAssertThrowsError(try PacketFilter("nonsense.field == 3"))
    }

    func testAnEmptyFilterMatchesEverything() throws {
        XCTAssertEqual(try PacketFilter("").apply(to: packets()).count, 3)
    }
}

final class AddressTests: XCTestCase {

    func testMACFormatting() {
        let mac = MACAddress([0x3c, 0x22, 0xfb, 0x11, 0x22, 0x33])
        XCTAssertEqual(mac.description, "3c:22:fb:11:22:33")
        XCTAssertEqual(mac.oui, "3C22FB")
        XCTAssertFalse(mac.isMulticast)
        XCTAssertTrue(MACAddress([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).isBroadcast)
    }

    func testLocallyAdministeredIsRecognised() {
        // The randomised addresses phones use, which no vendor lookup should touch.
        XCTAssertTrue(MACAddress([0x02, 0, 0, 0, 0, 0]).isLocallyAdministered)
        XCTAssertFalse(MACAddress([0x3c, 0x22, 0xfb, 0, 0, 0]).isLocallyAdministered)
    }

    func testMACParsingBothSeparators() {
        XCTAssertEqual(MACAddress(string: "3C-22-FB-11-22-33")?.description,
                       "3c:22:fb:11:22:33")
        XCTAssertNil(MACAddress(string: "3c:22:fb:11:22"))
    }

    func testIPv6Compression() {
        // The longest zero run collapses, and a single zero group does not.
        XCTAssertEqual(IPAddress(v6: [0x20, 0x01, 0x0d, 0xb8] + Array(repeating: 0, count: 11)
                                 + [1]).description, "2001:db8::1")
        XCTAssertEqual(IPAddress(v6: Array(repeating: 0, count: 15) + [1]).description, "::1")
    }

    func testPrivateRanges() {
        XCTAssertTrue(IPAddress(v4: [192, 168, 1, 1]).isPrivate)
        XCTAssertTrue(IPAddress(v4: [172, 20, 0, 1]).isPrivate)
        XCTAssertFalse(IPAddress(v4: [172, 32, 0, 1]).isPrivate)
        XCTAssertFalse(IPAddress(v4: [8, 8, 8, 8]).isPrivate)
    }
}

final class MacLinkTests: XCTestCase {

    func testParsesAPairingLink() {
        let parsed = MacLink.peer(fromPairingURL: "nettool://192.168.1.10:8765/?token=abc123")
        XCTAssertEqual(parsed?.0.host, "192.168.1.10")
        XCTAssertEqual(parsed?.0.port, 8765)
        XCTAssertEqual(parsed?.1, "abc123")
    }

    func testRejectsALinkWithNoToken() {
        XCTAssertNil(MacLink.peer(fromPairingURL: "nettool://192.168.1.10:8765/"))
        XCTAssertNil(MacLink.peer(fromPairingURL: "just some text"))
    }

    func testDefaultsThePort() {
        XCTAssertEqual(MacLink.peer(fromPairingURL: "nettool://mac.local/?token=x")?.0.port,
                       8765)
    }
}

final class SignalTests: XCTestCase {

    func testRatingThresholdsMatchTheOtherClients() {
        // The CLI and the Mac GUI use these same boundaries; three different
        // answers to "is this signal good" would be worse than none.
        XCTAssertEqual(SignalRating(dbm: -45), .excellent)
        XCTAssertEqual(SignalRating(dbm: -65), .good)
        XCTAssertEqual(SignalRating(dbm: -70), .fair)
        XCTAssertEqual(SignalRating(dbm: -80), .weak)
        XCTAssertEqual(SignalRating(dbm: -95), .unusable)
    }

    func testGaugeFractionIsClamped() {
        XCTAssertEqual(SignalRating.fraction(dbm: -30), 1.0)
        XCTAssertEqual(SignalRating.fraction(dbm: -120), 0.0)
        XCTAssertEqual(SignalRating.fraction(dbm: -60), 0.5, accuracy: 0.001)
    }
}

final class PingTests: XCTestCase {

    func testChecksumOfAKnownPacket() {
        // An all-zero body has a checksum of all ones, which is the easiest
        // case to get wrong when the carry fold is missing.
        XCTAssertEqual(Ping.checksum([0x00, 0x00, 0x00, 0x00]), 0xffff)
    }

    func testEchoRequestIsWellFormed() {
        let packet = Ping.echoRequest(identifier: 0x1234, sequence: 7, payloadSize: 4)
        XCTAssertEqual(packet[0], 8, "type 8 is echo request")
        XCTAssertEqual(packet[1], 0)
        XCTAssertEqual(packet.count, 12)
        // With the checksum in place, summing the whole packet gives all ones.
        XCTAssertEqual(Ping.checksum(packet), 0)
    }

    func testJitterIsTheMeanConsecutiveDelta() {
        var result = PingResult(host: "x", address: "x")
        result.rtts = [10, 12, 11]
        XCTAssertEqual(result.jitter ?? 0, 1.5, accuracy: 0.001)
    }
}
