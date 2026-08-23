import Foundation

/// Turns a captured frame into the flat record the app displays.
public enum PacketDecoder {

    public static func decode(_ packet: CapturedPacket) -> DecodedPacket {
        var decoded = DecodedPacket(id: packet.id,
                                    timestamp: packet.timestamp,
                                    length: packet.originalLength,
                                    capturedLength: packet.bytes.count)
        var reader = ByteReader(packet.bytes)
        do {
            switch packet.linkType {
            case .ethernet:
                try ethernet(&reader, into: &decoded)
            case .ieee802_11Radiotap:
                let radio = try Radiotap.parse(&reader)
                decoded.radio = radio
                try dot11(&reader, into: &decoded)
            case .ieee802_11:
                try dot11(&reader, into: &decoded)
            case .raw:
                try ip(&reader, into: &decoded)
            case .linuxSLL:
                try linuxCooked(&reader, into: &decoded)
            case .unknown:
                decoded.protocolName = "unknown link"
            }
        } catch {
            // A short frame is normal in a snaplen-limited capture; keep what
            // was decoded and say where it stopped rather than dropping the row.
            decoded.layers.append("truncated")
            if decoded.summary.isEmpty {
                decoded.summary = "truncated after \(decoded.layers.count) layers"
            }
        }
        if decoded.summary.isEmpty {
            decoded.summary = "\(decoded.protocolName) \(decoded.length) bytes"
        }
        return decoded
    }

    public static func decodeAll(_ file: CaptureFile) -> [DecodedPacket] {
        file.packets.map(decode)
    }

    // --- link layers -----------------------------------------------------

    static func ethernet(_ reader: inout ByteReader, into packet: inout DecodedPacket) throws {
        packet.layers.append("Ethernet")
        packet.destinationMAC = try reader.mac()
        packet.sourceMAC = try reader.mac()
        var etherType = try reader.u16()

        // 802.1Q, and QinQ: keep the outermost tag, which is the one that says
        // which VLAN the frame was actually seen on.
        while etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100 {
            let tag = try reader.u16()
            if packet.vlan == nil { packet.vlan = tag & 0x0fff }
            packet.layers.append("VLAN \(tag & 0x0fff)")
            etherType = try reader.u16()
        }
        try payload(etherType: etherType, &reader, into: &packet)
    }

    static func linuxCooked(_ reader: inout ByteReader, into packet: inout DecodedPacket) throws {
        packet.layers.append("Linux cooked")
        _ = try reader.u16()                       // packet type
        _ = try reader.u16()                       // ARPHRD
        let addressLength = Int(try reader.u16())
        let address = try reader.take(8)
        if addressLength == 6 { packet.sourceMAC = MACAddress(Array(address.prefix(6))) }
        try payload(etherType: try reader.u16(), &reader, into: &packet)
    }

    static func payload(etherType: UInt16, _ reader: inout ByteReader,
                        into packet: inout DecodedPacket) throws {
        switch etherType {
        case 0x0800, 0x86dd:
            try ip(&reader, into: &packet)
        case 0x0806:
            try arp(&reader, into: &packet)
        case 0x88cc:
            packet.protocolName = "LLDP"
            packet.layers.append("LLDP")
            packet.summary = "LLDP neighbour advertisement"
        case 0x8035:
            packet.protocolName = "RARP"
        case 0x888e:
            packet.protocolName = "EAPOL"
            packet.summary = "802.1X authentication"
        default:
            packet.protocolName = String(format: "0x%04x", etherType)
        }
        if packet.source.isEmpty {
            packet.source = packet.sourceMAC?.description ?? ""
            packet.destination = packet.destinationMAC?.description ?? ""
        }
    }

    // --- network ---------------------------------------------------------

    static func ip(_ reader: inout ByteReader, into packet: inout DecodedPacket) throws {
        let first = try reader.u8()
        let version = first >> 4
        if version == 4 {
            packet.layers.append("IPv4")
            let headerLength = Int(first & 0x0f) * 4
            _ = try reader.u8()                     // DSCP/ECN
            _ = try reader.u16()                    // total length
            _ = try reader.u32()                    // id, flags, fragment offset
            _ = try reader.u8()                     // TTL
            let proto = try reader.u8()
            _ = try reader.u16()                    // checksum
            packet.sourceIP = try reader.ipv4()
            packet.destinationIP = try reader.ipv4()
            try reader.skip(max(0, headerLength - 20))
            packet.source = packet.sourceIP?.description ?? ""
            packet.destination = packet.destinationIP?.description ?? ""
            try transport(proto: proto, &reader, into: &packet)
        } else if version == 6 {
            packet.layers.append("IPv6")
            try reader.skip(3)                      // rest of flow label
            _ = try reader.u16()                    // payload length
            let next = try reader.u8()
            _ = try reader.u8()                     // hop limit
            packet.sourceIP = try reader.ipv6()
            packet.destinationIP = try reader.ipv6()
            packet.source = packet.sourceIP?.description ?? ""
            packet.destination = packet.destinationIP?.description ?? ""
            try transport(proto: next, &reader, into: &packet)
        } else {
            packet.protocolName = "IP v\(version)?"
        }
    }

    static func arp(_ reader: inout ByteReader, into packet: inout DecodedPacket) throws {
        packet.layers.append("ARP")
        packet.protocolName = "ARP"
        _ = try reader.u16()                        // hardware type
        _ = try reader.u16()                        // protocol type
        _ = try reader.u8()                         // hardware size
        _ = try reader.u8()                         // protocol size
        let operation = try reader.u16()
        let senderMAC = try reader.mac()
        let senderIP = try reader.ipv4()
        let targetMAC = try reader.mac()
        let targetIP = try reader.ipv4()
        packet.arp = ARPMessage(isRequest: operation == 1, senderIP: senderIP,
                                senderMAC: senderMAC, targetIP: targetIP,
                                targetMAC: targetMAC)
        packet.source = senderIP.description
        packet.destination = targetIP.description
        packet.summary = operation == 1
            ? "Who has \(targetIP)? Tell \(senderIP)"
            : "\(senderIP) is at \(senderMAC)"
    }

    // --- transport -------------------------------------------------------

    static func transport(proto: UInt8, _ reader: inout ByteReader,
                          into packet: inout DecodedPacket) throws {
        switch proto {
        case 6:
            packet.layers.append("TCP")
            packet.protocolName = "TCP"
            let source = try reader.u16()
            let destination = try reader.u16()
            let sequence = try reader.u32()
            let acknowledgement = try reader.u32()
            let offsetByte = try reader.u8()
            let flags = try reader.u8()
            let window = try reader.u16()
            _ = try reader.u16()                    // checksum
            _ = try reader.u16()                    // urgent pointer
            let headerLength = Int(offsetByte >> 4) * 4
            try reader.skip(max(0, headerLength - 20))
            packet.sourcePort = source
            packet.destinationPort = destination
            packet.payloadRange = reader.offset..<reader.end
            let header = TCPHeader(sequence: sequence, acknowledgement: acknowledgement,
                                   flags: flags, window: window,
                                   payloadLength: reader.remaining)
            packet.tcp = header
            packet.summary = "\(source) -> \(destination) [\(header.flagNames)] "
                           + "seq=\(sequence) win=\(window) len=\(header.payloadLength)"
            packet.protocolName = serviceName(source, destination) ?? "TCP"

        case 17:
            packet.layers.append("UDP")
            packet.protocolName = "UDP"
            let source = try reader.u16()
            let destination = try reader.u16()
            _ = try reader.u16()                    // length
            _ = try reader.u16()                    // checksum
            packet.sourcePort = source
            packet.destinationPort = destination
            packet.payloadRange = reader.offset..<reader.end
            packet.summary = "\(source) -> \(destination) len=\(reader.remaining)"
            if source == 53 || destination == 53 || source == 5353 || destination == 5353 {
                var dnsReader = ByteReader(reader.bytes, from: reader.offset, to: reader.end)
                if let message = try? DNSMessage.parse(&dnsReader) {
                    packet.dns = message
                    packet.protocolName = (source == 5353 || destination == 5353)
                        ? "mDNS" : "DNS"
                    packet.summary = message.summary
                }
            } else {
                packet.protocolName = serviceName(source, destination) ?? "UDP"
            }

        case 1:
            packet.layers.append("ICMP")
            packet.protocolName = "ICMP"
            let type = try reader.u8()
            let code = try reader.u8()
            packet.summary = icmpName(type: type, code: code)

        case 58:
            packet.layers.append("ICMPv6")
            packet.protocolName = "ICMPv6"
            let type = try reader.u8()
            packet.summary = "ICMPv6 type \(type)"

        case 2:
            packet.protocolName = "IGMP"
        default:
            packet.protocolName = "IP proto \(proto)"
        }
    }

    // --- naming ----------------------------------------------------------

    static let services: [UInt16: String] = [
        20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
        161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 514: "syslog",
        587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
        1883: "MQTT", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL",
        5353: "mDNS", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    ]

    /// The better-known of the two ports names the row, since one of them is
    /// almost always an ephemeral source port that means nothing.
    static func serviceName(_ source: UInt16, _ destination: UInt16) -> String? {
        if let name = services[min(source, destination)] { return name }
        if let name = services[source] { return name }
        return services[destination]
    }

    static func icmpName(type: UInt8, code: UInt8) -> String {
        switch (type, code) {
        case (0, _): return "Echo reply"
        case (3, 0): return "Destination network unreachable"
        case (3, 1): return "Destination host unreachable"
        case (3, 3): return "Destination port unreachable"
        case (3, 4): return "Fragmentation needed but DF set"
        case (5, _): return "Redirect"
        case (8, _): return "Echo request"
        case (11, 0): return "TTL exceeded in transit"
        default: return "ICMP type \(type) code \(code)"
        }
    }
}
