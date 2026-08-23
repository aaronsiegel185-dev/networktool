import Foundation
import Network

public struct PortResult: Identifiable, Sendable {
    public var id: Int { port }
    public let port: Int
    public let isOpen: Bool
    public let service: String?
    public let milliseconds: Double
}

/// A TCP connect scan over Network.framework.
///
/// NWConnection rather than BSD sockets: it is the only path that behaves on a
/// phone moving between Wi-Fi and cellular, and it gets the app the local
/// network permission prompt at the right moment rather than failing silently.
public actor PortScanner {
    public init() {}

    public func scan(host: String, ports: [Int], timeout: TimeInterval = 1.0,
                     concurrency: Int = 24,
                     onResult: (@Sendable (PortResult) -> Void)? = nil) async -> [PortResult] {
        var results: [PortResult] = []
        var remaining = ports[...]

        while !remaining.isEmpty {
            let batch = Array(remaining.prefix(concurrency))
            remaining = remaining.dropFirst(batch.count)
            await withTaskGroup(of: PortResult.self) { group in
                for port in batch {
                    group.addTask {
                        await Self.probe(host: host, port: port, timeout: timeout)
                    }
                }
                for await result in group {
                    results.append(result)
                    onResult?(result)
                }
            }
        }
        return results.sorted { $0.port < $1.port }
    }

    static func probe(host: String, port: Int, timeout: TimeInterval) async -> PortResult {
        let started = Date()
        let service = PacketDecoder.services[UInt16(clamping: port)]
        guard let endpointPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else {
            return PortResult(port: port, isOpen: false, service: service, milliseconds: 0)
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort,
                                      using: .tcp)
        return await withCheckedContinuation { continuation in
            // The continuation must be resumed exactly once, and both the state
            // handler and the timeout race to do it.
            let finished = Locked(false)
            func finish(_ isOpen: Bool) {
                guard finished.exchange(true) == false else { return }
                connection.cancel()
                continuation.resume(returning: PortResult(
                    port: port, isOpen: isOpen, service: service,
                    milliseconds: Date().timeIntervalSince(started) * 1000))
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(true)
                case .failed, .cancelled: finish(false)
                case .waiting: finish(false)     // refused, or no route
                default: break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(false) }
        }
    }
}

/// A tiny mutex, so a continuation cannot be resumed twice.
final class Locked<Value>: @unchecked Sendable {
    private var value: Value
    private let lock = NSLock()

    init(_ value: Value) { self.value = value }

    func exchange(_ new: Value) -> Value {
        lock.lock()
        defer { lock.unlock() }
        let old = value
        value = new
        return old
    }
}
