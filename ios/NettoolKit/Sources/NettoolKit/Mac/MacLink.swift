import Combine
import Foundation
import Network

/// A nettool server found on the network.
public struct MacPeer: Identifiable, Hashable, Sendable {
    public var id: String { "\(name)@\(host):\(port)" }
    public let name: String
    public let host: String
    public let port: Int

    public init(name: String, host: String, port: Int) {
        self.name = name
        self.host = host
        self.port = port
    }
}

/// What `/hello` says about a server, before pairing.
public struct MacHello: Decodable, Sendable {
    public let service: String
    public let version: String
    public let api: String
    public let host: String
    public let platform: String
    public let interfaces: [String]
    public let capabilities: MacCapabilities
}

public struct MacCapabilities: Decodable, Sendable {
    public let capture: Bool
    public let capturableInterfaces: [String]
    public let monitorMode: Bool
    public let elevated: Bool

    enum CodingKeys: String, CodingKey {
        case capture
        case capturableInterfaces = "capturable_interfaces"
        case monitorMode = "monitor_mode"
        case elevated
    }
}

/// Talks to `nettool serve` on a Mac.
///
/// The phone can read a capture and run its own probes, but iOS will not give
/// any app a raw socket or a monitor-mode radio - so anything needing one is
/// asked of a real machine over this, and the app is honest about which of the
/// two answered.
public actor MacLink {
    public private(set) var peer: MacPeer?
    public private(set) var token: String?

    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func pair(with peer: MacPeer, token: String) {
        self.peer = peer
        self.token = token
    }

    public func unpair() {
        peer = nil
        token = nil
    }

    public var isPaired: Bool { peer != nil && token != nil }

    /// Parse a pairing link: `nettool://host:port/?token=...`
    ///
    /// Typing a token by hand on a phone is miserable, so the Mac prints this
    /// and the app takes it whole - from a QR code, a paste, or a tap.
    public static func peer(fromPairingURL text: String) -> (MacPeer, String)? {
        guard let url = URLComponents(string: text.trimmingCharacters(in: .whitespaces)),
              let host = url.host,
              let token = url.queryItems?.first(where: { $0.name == "token" })?.value,
              !token.isEmpty else { return nil }
        let port = url.port ?? 8765
        return (MacPeer(name: host, host: host, port: port), token)
    }

    /// Ask a server what it is. Deliberately unauthenticated, so the app can
    /// show what it found before anyone has pasted a token.
    public func hello(at peer: MacPeer) async throws -> MacHello {
        try await request("hello", peer: peer, authenticated: false)
    }

    public func interfaces() async throws -> [String: [InterfaceRecord]] {
        try await request("iface")
    }

    public func wifiAnalyze() async throws -> WifiReport {
        try await request("wifi/analyze")
    }

    public func captures() async throws -> CaptureListing {
        try await request("captures")
    }

    /// Run a capture on the Mac and bring the file back to the phone.
    public func capture(interface: String?, seconds: Int, filter: String?,
                        monitor: Bool = false) async throws -> CaptureFile {
        var query = [URLQueryItem(name: "duration", value: String(seconds))]
        if let interface { query.append(URLQueryItem(name: "interface", value: interface)) }
        if let filter, !filter.isEmpty {
            query.append(URLQueryItem(name: "filter", value: filter))
        }
        if monitor { query.append(URLQueryItem(name: "monitor", value: "1")) }
        let started: CaptureStarted = try await request("capture", query: query)
        let data = try await download(file: started.file)
        return try CaptureFile.read(data: data)
    }

    public func download(file name: String) async throws -> Data {
        guard let peer, let token else { throw NetworkToolError.notPaired }
        var components = URLComponents()
        components.scheme = "http"
        components.host = peer.host
        components.port = peer.port
        components.path = "/api/v1/download"
        components.queryItems = [URLQueryItem(name: "file", value: name),
                                 URLQueryItem(name: "token", value: token)]
        guard let url = components.url else { throw NetworkToolError.notPaired }
        let (data, response) = try await session.data(from: url)
        try check(response)
        return data
    }

    // --- plumbing --------------------------------------------------------

    private func request<T: Decodable>(_ path: String, peer explicit: MacPeer? = nil,
                                       query: [URLQueryItem] = [],
                                       authenticated: Bool = true) async throws -> T {
        guard let target = explicit ?? peer else { throw NetworkToolError.notPaired }
        var components = URLComponents()
        components.scheme = "http"
        components.host = target.host
        components.port = target.port
        components.path = "/api/v1/\(path)"
        if !query.isEmpty { components.queryItems = query }
        guard let url = components.url else { throw NetworkToolError.notPaired }

        var urlRequest = URLRequest(url: url)
        urlRequest.timeoutInterval = 180      // a capture holds the socket open
        if authenticated {
            guard let token else { throw NetworkToolError.notPaired }
            urlRequest.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        let (data, response) = try await session.data(for: urlRequest)
        try check(response, data: data)
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func check(_ response: URLResponse, data: Data? = nil) throws {
        guard let http = response as? HTTPURLResponse else { return }
        guard (200..<300).contains(http.statusCode) else {
            // The server explains itself in JSON; relaying that beats "status 400".
            if let data, let failure = try? JSONDecoder().decode(ServerError.self, from: data) {
                throw NetworkToolError.unavailable(failure.error)
            }
            if http.statusCode == 401 {
                throw NetworkToolError.unavailable("the Mac rejected the pairing token")
            }
            throw NetworkToolError.unavailable("the Mac answered \(http.statusCode)")
        }
    }

    private struct ServerError: Decodable { let error: String }
    private struct CaptureStarted: Decodable { let file: String }
}

// --- the shapes the server sends ------------------------------------------

/// Fields are defaulted rather than required: the server omits what a platform
/// cannot answer, and one missing key should not fail the whole decode.
public struct InterfaceRecord: Decodable, Sendable {
    public var name: String = ""
    public var ipv4: String = ""
    public var mac: String = ""
    public var up: Bool = false
    public var wireless: Bool = false

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        ipv4 = try container.decodeIfPresent(String.self, forKey: .ipv4) ?? ""
        mac = try container.decodeIfPresent(String.self, forKey: .mac) ?? ""
        up = try container.decodeIfPresent(Bool.self, forKey: .up) ?? false
        wireless = try container.decodeIfPresent(Bool.self, forKey: .wireless) ?? false
    }

    enum CodingKeys: String, CodingKey { case name, ipv4, mac, up, wireless }
}

public struct CaptureListing: Decodable, Sendable {
    public struct Entry: Decodable, Sendable, Identifiable {
        public var id: String { name }
        public let name: String
        public let bytes: Int
        public let modified: Double
    }
    public let directory: String
    public let captures: [Entry]
}

public struct WifiReport: Decodable, Sendable {
    public struct Network: Decodable, Sendable, Identifiable {
        public var id: String { "\(bssid)-\(channel ?? 0)-\(ssid)" }
        public var ssid: String = ""
        public var bssid: String = ""
        public var channel: Int?
        public var band: String = ""
        public var signalDBM: Double?

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            ssid = try container.decodeIfPresent(String.self, forKey: .ssid) ?? ""
            bssid = try container.decodeIfPresent(String.self, forKey: .bssid) ?? ""
            channel = try container.decodeIfPresent(Int.self, forKey: .channel)
            band = try container.decodeIfPresent(String.self, forKey: .band) ?? ""
            signalDBM = try container.decodeIfPresent(Double.self, forKey: .signalDBM)
        }

        enum CodingKeys: String, CodingKey {
            case ssid, bssid, channel, band
            case signalDBM = "signal_dbm"
        }
    }
    public let source: String
    public let networks: [Network]
}

/// Finds Macs running `nettool serve`, over Bonjour.
public final class MacBrowser: NSObject, ObservableObject, @unchecked Sendable {
    @Published public private(set) var peers: [MacPeer] = []
    @Published public private(set) var isSearching = false

    private var browser: NWBrowser?

    public override init() { super.init() }

    public func start() {
        guard browser == nil else { return }
        let parameters = NWParameters()
        parameters.includePeerToPeer = true
        let browser = NWBrowser(
            for: .bonjour(type: "_nettool._tcp", domain: nil), using: parameters)
        browser.stateUpdateHandler = { [weak self] state in
            DispatchQueue.main.async {
                self?.isSearching = (state == .ready)
            }
        }
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            let found: [MacPeer] = results.compactMap { result in
                guard case let .service(name, _, _, _) = result.endpoint else { return nil }
                // Bonjour gives a name; the address is resolved when we connect,
                // so the hostname form is what the request needs.
                return MacPeer(name: name, host: "\(name).local", port: 8765)
            }
            DispatchQueue.main.async {
                self?.peers = found.sorted { $0.name < $1.name }
            }
        }
        browser.start(queue: .main)
        self.browser = browser
    }

    public func stop() {
        browser?.cancel()
        browser = nil
        isSearching = false
    }
}
