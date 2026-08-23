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
        let service = PacketDecoder.services[UInt16(clamping: port)]
        guard let endpointPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else {
            return PortResult(port: port, isOpen: false, service: service, milliseconds: 0)
        }
        return await withCheckedContinuation { continuation in
            let probe = Probe(port: port, service: service, continuation: continuation)
            probe.start(host: host, port: endpointPort, timeout: timeout)
        }
    }
}

/// One port probe: owns the connection, and resumes its continuation exactly once.
///
/// A class rather than a local function, because the state handler and the
/// timeout race to finish the probe from two different queues. Resuming a
/// continuation twice is a crash, not a warning, so the "only once" has to be
/// enforced by something with a lock rather than by the order things happen in.
private final class Probe: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<PortResult, Never>?
    private var connection: NWConnection?
    private let port: Int
    private let service: String?
    private let started = Date()

    init(port: Int, service: String?,
         continuation: CheckedContinuation<PortResult, Never>) {
        self.port = port
        self.service = service
        self.continuation = continuation
    }

    func start(host: String, port endpointPort: NWEndpoint.Port, timeout: TimeInterval) {
        let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort,
                                      using: .tcp)
        lock.lock()
        self.connection = connection
        lock.unlock()

        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.finish(open: true)
            case .failed, .cancelled:
                self?.finish(open: false)
            case .waiting:
                // Refused, or no route to the host - either way, not open.
                self?.finish(open: false)
            default:
                break
            }
        }
        connection.start(queue: .global(qos: .userInitiated))
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
            self?.finish(open: false)
        }
    }

    private func finish(open: Bool) {
        lock.lock()
        let pending = continuation
        let live = connection
        continuation = nil
        connection = nil
        lock.unlock()

        // Whoever got here second finds nothing to do, which is the point.
        guard let pending else { return }
        live?.cancel()
        pending.resume(returning: PortResult(
            port: port, isOpen: open, service: service,
            milliseconds: Date().timeIntervalSince(started) * 1000))
    }
}
