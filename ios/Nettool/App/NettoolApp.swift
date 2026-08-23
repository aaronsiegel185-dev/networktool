import SwiftUI
import NettoolKit

@main
struct NettoolApp: App {
    @StateObject private var store = AppStore()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
        }
    }
}

/// The app's shared state.
///
/// One store rather than per-screen state, because the same capture is looked
/// at from the packet list, the conversations and Follow Stream, and decoding a
/// large file twice is the difference between instant and a spinner.
@MainActor
final class AppStore: ObservableObject {
    @Published var capture: CaptureFile?
    @Published var packets: [DecodedPacket] = []
    @Published var analysis: Analysis?
    @Published var captureName: String = ""
    @Published var isLoading = false
    @Published var loadError: String?

    @Published var macLink = MacLink()
    @Published var pairedPeer: MacPeer?
    @Published var macCapabilities: MacCapabilities?

    private let defaults = UserDefaults.standard

    init() {
        restorePairing()
    }

    func load(url: URL) async {
        isLoading = true
        loadError = nil
        defer { isLoading = false }
        do {
            // Off the main actor: a 200k-packet file takes seconds to decode and
            // the list should not freeze while it happens.
            let file = try await Task.detached(priority: .userInitiated) {
                try CaptureFile.read(url: url)
            }.value
            await adopt(file, named: url.lastPathComponent)
        } catch {
            loadError = error.localizedDescription
        }
    }

    func adopt(_ file: CaptureFile, named name: String) async {
        let decoded = await Task.detached(priority: .userInitiated) {
            PacketDecoder.decodeAll(file)
        }.value
        let summary = await Task.detached(priority: .userInitiated) {
            Analyzer.analyze(decoded)
        }.value
        capture = file
        packets = decoded
        analysis = summary
        captureName = name
    }

    // --- pairing ---------------------------------------------------------

    func pair(peer: MacPeer, token: String) async {
        await macLink.pair(with: peer, token: token)
        pairedPeer = peer
        defaults.set(peer.host, forKey: "mac.host")
        defaults.set(peer.port, forKey: "mac.port")
        defaults.set(peer.name, forKey: "mac.name")
        // The token is a bearer credential for a machine on the user's own
        // network. UserDefaults is the wrong place for it; the keychain is the
        // right one and is what this uses.
        Keychain.set(token, for: "mac.token")
    }

    func unpair() async {
        await macLink.unpair()
        pairedPeer = nil
        macCapabilities = nil
        Keychain.remove("mac.token")
        defaults.removeObject(forKey: "mac.host")
    }

    private func restorePairing() {
        guard let host = defaults.string(forKey: "mac.host"),
              let token = Keychain.get("mac.token") else { return }
        let peer = MacPeer(name: defaults.string(forKey: "mac.name") ?? host,
                           host: host,
                           port: defaults.integer(forKey: "mac.port"))
        pairedPeer = peer
        Task { await macLink.pair(with: peer, token: token) }
    }
}

/// The keychain, for the one secret this app holds.
enum Keychain {
    private static let service = "dev.nettool.ios"

    static func set(_ value: String, for account: String) {
        remove(account)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: Data(value.utf8),
            // Never leaves this device, and only readable once unlocked.
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    static func get(_ account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    static func remove(_ account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
