import Foundation

/// A small display filter, in the shape people already type into Wireshark.
///
/// Not BPF and not a full expression language: terms separated by `and`/`or`,
/// each `field op value` or a bare protocol name, with `not` to invert. That
/// covers what anyone actually types on a phone, and every term that does not
/// parse is reported rather than silently matching everything.
public struct PacketFilter {
    public enum Failure: Error, LocalizedError {
        case unknownTerm(String)

        public var errorDescription: String? {
            switch self {
            case let .unknownTerm(term): return "cannot understand \"\(term)\""
            }
        }
    }

    private enum Combinator { case and, or }

    private struct Term {
        let negated: Bool
        let test: (DecodedPacket) -> Bool
    }

    private let terms: [Term]
    private let combinator: Combinator
    public let source: String

    public init(_ expression: String) throws {
        source = expression
        let lowered = expression.lowercased()
        let useOr = lowered.contains(" or ")
        combinator = useOr ? .or : .and
        let separator = useOr ? " or " : " and "
        let pieces = lowered
            .components(separatedBy: separator)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        var built: [Term] = []
        for piece in pieces {
            var text = piece
            var negated = false
            for prefix in ["not ", "!"] where text.hasPrefix(prefix) {
                negated = true
                text = String(text.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
            }
            guard let test = Self.term(text) else { throw Failure.unknownTerm(piece) }
            built.append(Term(negated: negated, test: test))
        }
        terms = built
    }

    public func matches(_ packet: DecodedPacket) -> Bool {
        guard !terms.isEmpty else { return true }
        switch combinator {
        case .and: return terms.allSatisfy { $0.negated != $0.test(packet) }
        case .or: return terms.contains { $0.negated != $0.test(packet) }
        }
    }

    public func apply(to packets: [DecodedPacket]) -> [DecodedPacket] {
        packets.filter(matches)
    }

    private static func term(_ text: String) -> ((DecodedPacket) -> Bool)? {
        // field op value
        for op in ["==", "!=", ">=", "<=", "=", ">", "<"] {
            guard let range = text.range(of: op) else { continue }
            let field = String(text[text.startIndex..<range.lowerBound])
                .trimmingCharacters(in: .whitespaces)
            let value = String(text[range.upperBound...])
                .trimmingCharacters(in: .whitespaces)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            return comparison(field: field, op: op, value: value)
        }
        // A bare word is a protocol or a layer name.
        return { packet in
            packet.protocolName.lowercased() == text
                || packet.layers.contains { $0.lowercased().hasPrefix(text) }
        }
    }

    private static func comparison(field: String, op: String,
                                   value: String) -> ((DecodedPacket) -> Bool)? {
        func compareNumbers(_ lhs: Int?, _ rhs: Int) -> Bool {
            guard let lhs else { return false }
            switch op {
            case ">": return lhs > rhs
            case "<": return lhs < rhs
            case ">=": return lhs >= rhs
            case "<=": return lhs <= rhs
            case "!=": return lhs != rhs
            default: return lhs == rhs
            }
        }
        func compareText(_ lhs: String) -> Bool {
            op == "!=" ? lhs.lowercased() != value : lhs.lowercased() == value
        }

        switch field {
        case "ip", "addr", "host", "ip.addr":
            return { compareText($0.source) || compareText($0.destination) }
        case "ip.src", "src":
            return { compareText($0.source) }
        case "ip.dst", "dst":
            return { compareText($0.destination) }
        case "port", "tcp.port", "udp.port":
            guard let wanted = Int(value) else { return nil }
            return {
                compareNumbers($0.sourcePort.map(Int.init), wanted)
                    || compareNumbers($0.destinationPort.map(Int.init), wanted)
            }
        case "len", "frame.len":
            guard let wanted = Int(value) else { return nil }
            return { compareNumbers($0.length, wanted) }
        case "vlan":
            guard let wanted = Int(value) else { return nil }
            return { compareNumbers($0.vlan.map(Int.init), wanted) }
        case "proto", "protocol":
            return { compareText($0.protocolName) }
        case "mac", "eth.addr":
            return {
                compareText($0.sourceMAC?.description ?? "")
                    || compareText($0.destinationMAC?.description ?? "")
            }
        case "dns.name", "dns":
            return { packet in
                guard let name = packet.dns?.questions.first?.name else { return false }
                return op == "!=" ? !name.lowercased().contains(value)
                                  : name.lowercased().contains(value)
            }
        case "ssid":
            return { packet in
                guard let ssid = packet.wireless?.ssid else { return false }
                return op == "!=" ? ssid.lowercased() != value : ssid.lowercased() == value
            }
        case "tcp.flags":
            return { packet in
                guard let tcp = packet.tcp else { return false }
                return tcp.flagNames.lowercased().contains(value)
            }
        default:
            return nil
        }
    }
}
