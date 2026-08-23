import Foundation
#if canImport(NetworkExtension)
import NetworkExtension
#endif
#if canImport(SystemConfiguration_CaptiveNetwork)
import SystemConfiguration.CaptiveNetwork
#endif

/// What the phone can say about its own Wi-Fi link.
public struct WiFiLink: Sendable {
    public var ssid: String?
    public var bssid: String?
    public var isSecure: Bool?

    /// Whether any of this required an entitlement Apple has to grant.
    public var needsEntitlement: Bool
}

/// Wi-Fi facts from the phone itself.
///
/// This is the one place the two tiers differ. Reading your own SSID needs the
/// `com.apple.developer.networking.wifi-info` entitlement, which a free Apple
/// ID cannot provision - so the whole thing is behind a compile flag:
///
///   * built without `NETTOOL_ENTITLED`, the app never calls the API, never
///     asks for location, and reports "unavailable on this build". Everything
///     else - captures, decoding, ping, scans, the Mac companion - works,
///     because none of it needs Apple's permission.
///   * built with it (a paid account, entitlement added to the App ID), the
///     same screens fill in.
///
/// Doing it this way rather than at runtime matters: an entitlement the profile
/// does not carry makes the *build* fail to install, not the call fail. The
/// free tier has to not reference it at all.
public enum WiFiInfo {

    public static var isSupported: Bool {
        #if NETTOOL_ENTITLED
        return true
        #else
        return false
        #endif
    }

    /// Why the Wi-Fi screens are limited, in words worth showing a user.
    public static var limitation: String {
        #if NETTOOL_ENTITLED
        return ""
        #else
        return """
        iOS only tells an app the name of the Wi-Fi it is on if that app carries \
        Apple's wifi-info entitlement, which needs a paid developer account. This \
        build does not have it, so the network's name and signal come from a \
        paired Mac instead - everything else on this screen is measured from the \
        phone.
        """
        #endif
    }

    public static func current() async -> WiFiLink {
        #if NETTOOL_ENTITLED
        if #available(iOS 14.0, *) {
            let network = await NEHotspotNetwork.fetchCurrent()
            return WiFiLink(ssid: network?.ssid,
                            bssid: network?.bssid,
                            isSecure: network?.isSecure,
                            needsEntitlement: true)
        }
        #endif
        return WiFiLink(ssid: nil, bssid: nil, isSecure: nil, needsEntitlement: true)
    }
}

/// Signal quality, rated the same way the CLI and the Mac GUI rate it, so the
/// three never disagree about what "good" means.
public enum SignalRating: String, Sendable, CaseIterable {
    case excellent, good, fair, weak, unusable

    public init(dbm: Double) {
        switch dbm {
        case (-60)...: self = .excellent
        case (-67)..<(-60): self = .good
        case (-75)..<(-67): self = .fair
        case (-85)..<(-75): self = .weak
        default: self = .unusable
        }
    }

    /// 0...1, for a gauge. Anchored at -90 and -30 dBm, which is the usable
    /// span of a phone radio rather than the theoretical one.
    public static func fraction(dbm: Double) -> Double {
        min(1, max(0, (dbm + 90) / 60))
    }

    public var advice: String {
        switch self {
        case .excellent: return "Plenty of signal. Anything slow here is not the radio."
        case .good: return "Comfortable for video and calls."
        case .fair: return "Workable, but below the -67 dBm floor for voice and video."
        case .weak: return "Too weak to be reliable - move closer or add an access point."
        case .unusable: return "Barely associated. Expect drops."
        }
    }
}
