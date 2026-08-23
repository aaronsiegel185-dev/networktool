import SwiftUI
import NettoolKit

/// What the phone can say about the radio it is on - and, where iOS will not
/// say, what a paired Mac says instead.
struct WiFiTab: View {
    @EnvironmentObject private var store: AppStore
    @State private var link: WiFiLink?
    @State private var macReport: WifiReport?
    @State private var isLoading = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                if !WiFiInfo.isSupported {
                    Section {
                        Text(WiFiInfo.limitation)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    } header: {
                        Label("Limited on this build", systemImage: "lock")
                    }
                }

                if let link, let ssid = link.ssid {
                    Section("This phone") {
                        FactRow(label: "Network", value: ssid)
                        if let bssid = link.bssid {
                            FactRow(label: "Access point", value: bssid, monospaced: true)
                        }
                        if let secure = link.isSecure {
                            FactRow(label: "Encrypted", value: secure ? "yes" : "no - open")
                        }
                    }
                }

                if let report = macReport {
                    Section("Seen by the Mac (\(report.source))") {
                        ForEach(report.networks.sorted {
                            ($0.signalDBM ?? -100) > ($1.signalDBM ?? -100)
                        }) { network in
                            NetworkRow(network: network)
                        }
                    }
                } else if store.pairedPeer != nil {
                    Section {
                        Button {
                            Task { await refresh() }
                        } label: {
                            Label("Scan from the Mac", systemImage: "antenna.radiowaves.left.and.right")
                        }
                        .disabled(isLoading)
                    } footer: {
                        Text("A phone cannot scan for other networks - iOS has no API "
                             + "for it at any tier. The paired Mac can, so the survey "
                             + "comes from there.")
                    }
                } else {
                    Section {
                        Text("Pair a Mac on the Mac tab to survey the air around you.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }

                if let error {
                    Section { Text(error).foregroundStyle(.red).font(.callout) }
                }
            }
            .navigationTitle("Wi-Fi")
            .refreshable { await refresh() }
            .task { await refresh() }
        }
    }

    private func refresh() async {
        isLoading = true
        defer { isLoading = false }
        link = await WiFiInfo.current()
        guard store.pairedPeer != nil else { return }
        do {
            macReport = try await store.macLink.wifiAnalyze()
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct NetworkRow: View {
    let network: WifiReport.Network

    var body: some View {
        HStack(spacing: 12) {
            SignalGauge(dbm: network.signalDBM)
                .frame(width: 42, height: 42)
            VStack(alignment: .leading, spacing: 2) {
                Text(network.ssid.isEmpty ? "(hidden)" : network.ssid)
                    .font(.callout.weight(.medium))
                    .lineLimit(1)
                Text(network.bssid).font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                HStack(spacing: 8) {
                    if let channel = network.channel {
                        Text("ch \(channel)")
                    }
                    if !network.band.isEmpty { Text("\(network.band) GHz") }
                    if let dbm = network.signalDBM {
                        Text(String(format: "%.0f dBm", dbm))
                            .foregroundStyle(Palette.color(forSignal: dbm))
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }
}

/// A dial rather than bars: bars imply five equal steps, and signal is not
/// linear - the difference between -50 and -60 matters far less than between
/// -70 and -80, which the arc's colour carries.
struct SignalGauge: View {
    let dbm: Double?

    var body: some View {
        ZStack {
            Circle()
                .trim(from: 0.1, to: 0.9)
                .stroke(Color.secondary.opacity(0.2), style: .init(lineWidth: 5,
                                                                   lineCap: .round))
                .rotationEffect(.degrees(90))
            if let dbm {
                Circle()
                    .trim(from: 0.1, to: 0.1 + 0.8 * SignalRating.fraction(dbm: dbm))
                    .stroke(Palette.color(forSignal: dbm), style: .init(lineWidth: 5,
                                                                        lineCap: .round))
                    .rotationEffect(.degrees(90))
                Text(String(format: "%.0f", dbm))
                    .font(.caption2.monospaced().weight(.medium))
            } else {
                Text("?").font(.caption2).foregroundStyle(.secondary)
            }
        }
    }
}
