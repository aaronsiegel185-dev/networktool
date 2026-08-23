import Foundation

public struct PingResult: Sendable {
    public var host: String
    public var address: String
    public var sent = 0
    public var received = 0
    public var rtts: [Double] = []

    public var lossPercent: Double {
        sent > 0 ? Double(sent - received) / Double(sent) * 100 : 0
    }
    public var minimum: Double? { rtts.min() }
    public var maximum: Double? { rtts.max() }
    public var average: Double? {
        rtts.isEmpty ? nil : rtts.reduce(0, +) / Double(rtts.count)
    }

    /// Mean deviation between consecutive round trips - the number that
    /// actually predicts whether a call will sound bad.
    public var jitter: Double? {
        guard rtts.count > 1 else { return nil }
        let deltas = zip(rtts, rtts.dropFirst()).map { abs($1 - $0) }
        return deltas.reduce(0, +) / Double(deltas.count)
    }
}

/// ICMP echo from an unprivileged process.
///
/// iOS never grants a raw socket, but Darwin allows SOCK_DGRAM with
/// IPPROTO_ICMP to anyone: the kernel writes the identifier and checks replies
/// on the socket's behalf, so this is real ICMP rather than a TCP connect
/// dressed up as a ping.
public actor Ping {
    public init() {}

    public func run(host: String, count: Int = 5, timeout: TimeInterval = 1.0,
                    interval: TimeInterval = 0.5,
                    onReply: (@Sendable (Int, Double?) -> Void)? = nil) async throws -> PingResult {
        let address = try Self.resolve(host)
        var result = PingResult(host: host, address: Self.describe(address))

        let handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard handle >= 0 else {
            throw NetworkToolError.unavailable(
                "the system refused an ICMP socket (errno \(errno))")
        }
        defer { close(handle) }

        var deadline = timeval(tv_sec: Int(timeout),
                               tv_usec: Int32((timeout - floor(timeout)) * 1_000_000))
        setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO, &deadline,
                   socklen_t(MemoryLayout<timeval>.size))

        for sequence in 0..<count {
            let packet = Self.echoRequest(identifier: UInt16.random(in: 0...UInt16.max),
                                          sequence: UInt16(sequence))
            let sentAt = Date()
            var target = address
            let written = packet.withUnsafeBytes { buffer in
                withUnsafePointer(to: &target) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                        sendto(handle, buffer.baseAddress, buffer.count, 0,
                               sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            guard written > 0 else { continue }
            result.sent += 1

            var reply = [UInt8](repeating: 0, count: 1500)
            let read = recv(handle, &reply, reply.count, 0)
            if read > 0 {
                let elapsed = Date().timeIntervalSince(sentAt) * 1000
                result.received += 1
                result.rtts.append(elapsed)
                onReply?(sequence, elapsed)
            } else {
                onReply?(sequence, nil)
            }
            if sequence < count - 1 {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            }
        }
        return result
    }

    /// An ICMP echo request. The kernel rewrites the identifier and the
    /// checksum for a datagram socket, but a correct one costs nothing and
    /// keeps the same builder usable elsewhere.
    static func echoRequest(identifier: UInt16, sequence: UInt16,
                            payloadSize: Int = 56) -> [UInt8] {
        var packet: [UInt8] = [8, 0, 0, 0]
        packet += [UInt8(identifier >> 8), UInt8(identifier & 0xff)]
        packet += [UInt8(sequence >> 8), UInt8(sequence & 0xff)]
        packet += (0..<payloadSize).map { UInt8($0 % 256) }
        let sum = checksum(packet)
        packet[2] = UInt8(sum >> 8)
        packet[3] = UInt8(sum & 0xff)
        return packet
    }

    /// The standard one's-complement checksum, with the carries folded back in.
    public static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var total: UInt32 = 0
        var index = 0
        while index + 1 < bytes.count {
            total += UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count { total += UInt32(bytes[index]) << 8 }
        while total >> 16 != 0 { total = (total & 0xffff) + (total >> 16) }
        return UInt16(truncatingIfNeeded: ~total)
    }

    static func resolve(_ host: String) throws -> sockaddr_in {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_DGRAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil,
                             ai_addr: nil, ai_next: nil)
        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &info) == 0, let first = info else {
            throw NetworkToolError.resolutionFailed(host)
        }
        defer { freeaddrinfo(info) }
        return first.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
            $0.pointee
        }
    }

    static func describe(_ address: sockaddr_in) -> String {
        var copy = address.sin_addr
        var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &copy, &text, socklen_t(INET_ADDRSTRLEN))
        return String(cString: text)
    }
}

public enum NetworkToolError: Error, LocalizedError {
    case unavailable(String)
    case resolutionFailed(String)
    case notPaired

    public var errorDescription: String? {
        switch self {
        case let .unavailable(what): return what
        case let .resolutionFailed(host): return "cannot resolve \(host)"
        case .notPaired: return "not paired with a Mac yet"
        }
    }
}
