import Foundation

/// Two endpoints and what passed between them.
public struct Conversation: Identifiable, Sendable {
    public let id: String
    public var endpointA: String
    public var endpointB: String
    public var protocolName: String
    public var packetsAtoB = 0
    public var packetsBtoA = 0
    public var bytesAtoB = 0
    public var bytesBtoA = 0
    public var firstSeen: Date
    public var lastSeen: Date

    public var packets: Int { packetsAtoB + packetsBtoA }
    public var bytes: Int { bytesAtoB + bytesBtoA }
    public var duration: TimeInterval { lastSeen.timeIntervalSince(firstSeen) }

    /// Traffic in one direction only - a scan, a black hole, or a reply path
    /// that is not coming back through here.
    public var isOneSided: Bool { packetsAtoB == 0 || packetsBtoA == 0 }

    public var bitsPerSecond: Double {
        duration > 0 ? Double(bytes * 8) / duration : 0
    }
}

public struct Endpoint: Identifiable, Sendable {
    public let id: String
    public var address: String
    public var packetsSent = 0
    public var packetsReceived = 0
    public var bytesSent = 0
    public var bytesReceived = 0
    public var peers: Set<String> = []

    public var packets: Int { packetsSent + packetsReceived }
    public var bytes: Int { bytesSent + bytesReceived }
}

public struct Finding: Identifiable, Sendable {
    public enum Severity: String, Sendable, CaseIterable {
        case ok, info, warn, critical
    }

    public let id = UUID()
    public let severity: Severity
    public let message: String

    public init(_ severity: Severity, _ message: String) {
        self.severity = severity
        self.message = message
    }
}

/// Everything the app derives from a decoded capture in one pass.
public struct Analysis: Sendable {
    public var packetCount = 0
    public var byteCount = 0
    public var duration: TimeInterval = 0
    public var conversations: [Conversation] = []
    public var endpoints: [Endpoint] = []
    public var protocolCounts: [String: Int] = [:]
    public var protocolBytes: [String: Int] = [:]
    public var findings: [Finding] = []

    public var retransmissions = 0
    public var duplicateAcks = 0
    public var resets = 0
    public var zeroWindows = 0
    public var failedHandshakes = 0
    public var dnsQueries = 0
    public var dnsFailures = 0

    public var averagePacketSize: Int {
        packetCount > 0 ? byteCount / packetCount : 0
    }
}

public enum Analyzer {

    /// One pass over the packets, building every summary the app shows.
    ///
    /// Deliberately a single traversal: a capture off a busy link is hundreds of
    /// thousands of frames, and the phone does this on the main actor's clock.
    public static func analyze(_ packets: [DecodedPacket]) -> Analysis {
        var analysis = Analysis()
        guard !packets.isEmpty else { return analysis }

        var conversations: [String: Conversation] = [:]
        var endpoints: [String: Endpoint] = [:]
        // Highest sequence seen per direction: a segment carrying data at or
        // below it is a retransmission.
        var highestSequence: [String: UInt32] = [:]
        var lastAck: [String: (ack: UInt32, count: Int)] = [:]
        var synsWithoutReply: Set<String> = []
        var completedHandshakes: Set<String> = []

        analysis.packetCount = packets.count
        analysis.duration = packets.last!.timestamp.timeIntervalSince(packets.first!.timestamp)

        for packet in packets {
            analysis.byteCount += packet.length
            analysis.protocolCounts[packet.protocolName, default: 0] += 1
            analysis.protocolBytes[packet.protocolName, default: 0] += packet.length

            let a = packet.source.isEmpty ? (packet.sourceMAC?.description ?? "?") : packet.source
            let b = packet.destination.isEmpty
                ? (packet.destinationMAC?.description ?? "?") : packet.destination
            let key = packet.conversationKey
            let forward = a < b

            var conversation = conversations[key] ?? Conversation(
                id: key,
                endpointA: forward ? a : b,
                endpointB: forward ? b : a,
                protocolName: packet.protocolName,
                firstSeen: packet.timestamp,
                lastSeen: packet.timestamp)
            if forward {
                conversation.packetsAtoB += 1
                conversation.bytesAtoB += packet.length
            } else {
                conversation.packetsBtoA += 1
                conversation.bytesBtoA += packet.length
            }
            conversation.lastSeen = packet.timestamp
            conversations[key] = conversation

            for (address, isSource) in [(a, true), (b, false)] {
                var endpoint = endpoints[address] ?? Endpoint(id: address, address: address)
                if isSource {
                    endpoint.packetsSent += 1
                    endpoint.bytesSent += packet.length
                    endpoint.peers.insert(b)
                } else {
                    endpoint.packetsReceived += 1
                    endpoint.bytesReceived += packet.length
                    endpoint.peers.insert(a)
                }
                endpoints[address] = endpoint
            }

            if let tcp = packet.tcp, let stream = packet.streamKey {
                let direction = "\(stream)|\(a)"
                if tcp.payloadLength > 0 || tcp.isSYN || tcp.isFIN {
                    let previous = highestSequence[direction]
                    if let previous, tcp.sequence < previous {
                        analysis.retransmissions += 1
                    }
                    highestSequence[direction] = max(previous ?? 0,
                                                     tcp.sequence &+ UInt32(tcp.payloadLength))
                }
                if tcp.isRST { analysis.resets += 1 }
                if tcp.window == 0 && !tcp.isRST { analysis.zeroWindows += 1 }
                if tcp.isACK && tcp.payloadLength == 0 && !tcp.isSYN && !tcp.isFIN {
                    var seen = lastAck[direction] ?? (tcp.acknowledgement, 0)
                    if seen.ack == tcp.acknowledgement {
                        seen.count += 1
                        // The first repeat is normal; three of the same ACK is
                        // the classic fast-retransmit signal.
                        if seen.count >= 2 { analysis.duplicateAcks += 1 }
                    } else {
                        seen = (tcp.acknowledgement, 0)
                    }
                    lastAck[direction] = seen
                }
                if tcp.isSYN && !tcp.isACK { synsWithoutReply.insert(stream) }
                if tcp.isSYN && tcp.isACK { completedHandshakes.insert(stream) }
            }

            if let dns = packet.dns {
                if dns.isResponse {
                    if dns.failed { analysis.dnsFailures += 1 }
                } else {
                    analysis.dnsQueries += 1
                }
            }
        }

        analysis.failedHandshakes = synsWithoutReply.subtracting(completedHandshakes).count
        analysis.conversations = conversations.values.sorted { $0.bytes > $1.bytes }
        analysis.endpoints = endpoints.values.sorted { $0.bytes > $1.bytes }
        analysis.findings = findings(for: analysis)
        return analysis
    }

    static func findings(for analysis: Analysis) -> [Finding] {
        var findings: [Finding] = []
        let packets = max(1, analysis.packetCount)

        let retransmissionRate = Double(analysis.retransmissions) / Double(packets) * 100
        if retransmissionRate > 5 {
            findings.append(Finding(.critical, String(
                format: "%.1f%% of packets are retransmissions (%d) - the path is losing data.",
                retransmissionRate, analysis.retransmissions)))
        } else if analysis.retransmissions > 0 {
            findings.append(Finding(.warn, String(
                format: "%d retransmissions (%.1f%%).",
                analysis.retransmissions, retransmissionRate)))
        }
        if analysis.duplicateAcks > 0 {
            findings.append(Finding(.warn,
                "\(analysis.duplicateAcks) duplicate ACKs - the receiver is asking for a gap to be refilled."))
        }
        if analysis.zeroWindows > 0 {
            findings.append(Finding(.critical,
                "\(analysis.zeroWindows) zero-window advertisements - a receiver stopped reading, so the sender had to stall."))
        }
        if analysis.resets > 0 {
            findings.append(Finding(.warn,
                "\(analysis.resets) connection resets - something refused or tore down a connection."))
        }
        if analysis.failedHandshakes > 0 {
            findings.append(Finding(.critical,
                "\(analysis.failedHandshakes) connections were opened but never answered - a firewall or a dead listener."))
        }
        if analysis.dnsFailures > 0 {
            findings.append(Finding(.warn,
                "\(analysis.dnsFailures) DNS lookups failed out of \(analysis.dnsQueries)."))
        }
        let oneSided = analysis.conversations.filter { $0.isOneSided && $0.packets > 4 }
        if oneSided.count > 3 {
            findings.append(Finding(.info,
                "\(oneSided.count) conversations only ever went one way - a scan, or replies taking another path."))
        }
        if findings.isEmpty {
            findings.append(Finding(.ok, "No obvious transport problems in this capture."))
        }
        return findings
    }
}
