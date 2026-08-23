import Foundation

/// Enough DNS to answer "what was asked, what came back, and how long it took".
public struct DNSMessage: Sendable {
    public struct Question: Sendable {
        public let name: String
        public let type: UInt16
        public var typeName: String { DNSMessage.typeName(type) }
    }

    public let id: UInt16
    public let isResponse: Bool
    public let responseCode: UInt8
    public let questions: [Question]
    public let answerCount: Int

    public var responseCodeName: String {
        switch responseCode {
        case 0: return "NOERROR"
        case 1: return "FORMERR"
        case 2: return "SERVFAIL"
        case 3: return "NXDOMAIN"
        case 4: return "NOTIMP"
        case 5: return "REFUSED"
        default: return "RCODE \(responseCode)"
        }
    }

    public var failed: Bool { isResponse && responseCode != 0 }

    public var summary: String {
        let name = questions.first?.name ?? "?"
        let type = questions.first?.typeName ?? "?"
        if isResponse {
            return "response \(type) \(name) -> \(responseCodeName) (\(answerCount) answers)"
        }
        return "query \(type) \(name)"
    }

    public static func typeName(_ type: UInt16) -> String {
        switch type {
        case 1: return "A"
        case 2: return "NS"
        case 5: return "CNAME"
        case 6: return "SOA"
        case 12: return "PTR"
        case 15: return "MX"
        case 16: return "TXT"
        case 28: return "AAAA"
        case 33: return "SRV"
        case 65: return "HTTPS"
        case 255: return "ANY"
        default: return "TYPE\(type)"
        }
    }

    public static func parse(_ reader: inout ByteReader) throws -> DNSMessage {
        let id = try reader.u16()
        let flags = try reader.u16()
        let questionCount = Int(try reader.u16())
        let answerCount = Int(try reader.u16())
        _ = try reader.u16()                        // authority count
        _ = try reader.u16()                        // additional count

        var questions: [Question] = []
        // A malformed count must not turn into a long loop over garbage.
        for _ in 0..<min(questionCount, 16) {
            guard reader.remaining > 0 else { break }
            let name = try readName(&reader)
            guard reader.remaining >= 4 else { break }
            let type = try reader.u16()
            _ = try reader.u16()                    // class
            questions.append(Question(name: name, type: type))
        }
        return DNSMessage(id: id,
                          isResponse: flags & 0x8000 != 0,
                          responseCode: UInt8(flags & 0x000f),
                          questions: questions,
                          answerCount: answerCount)
    }

    /// A DNS name, following compression pointers.
    ///
    /// Pointers can legally point backwards to any earlier label, and a hostile
    /// or corrupt packet can make them point in a loop - so every jump is
    /// counted and the whole thing gives up rather than spinning.
    static func readName(_ reader: inout ByteReader) throws -> String {
        var labels: [String] = []
        var jumps = 0
        var cursor = reader
        var jumped = false

        while true {
            let length = try cursor.u8()
            if length == 0 { break }
            if length & 0xc0 == 0xc0 {
                let low = try cursor.u8()
                let target = Int(UInt16(length & 0x3f) << 8 | UInt16(low))
                if !jumped {
                    reader = cursor                 // the caller resumes after the pointer
                    jumped = true
                }
                jumps += 1
                guard jumps < 16, target < cursor.bytes.count else {
                    return labels.joined(separator: ".")
                }
                cursor = ByteReader(cursor.bytes, from: target, to: cursor.end)
                continue
            }
            let raw = try cursor.take(Int(length))
            labels.append(String(decoding: raw, as: UTF8.self))
        }
        if !jumped { reader = cursor }
        return labels.isEmpty ? "." : labels.joined(separator: ".")
    }
}
