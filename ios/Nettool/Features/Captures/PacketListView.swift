import SwiftUI
import NettoolKit

struct PacketListView: View {
    @EnvironmentObject private var store: AppStore
    @State private var filterText = ""
    @State private var filterError: String?
    @State private var filtered: [DecodedPacket] = []

    var body: some View {
        VStack(spacing: 0) {
            filterBar
            List(filtered) { packet in
                NavigationLink {
                    PacketDetailView(packet: packet)
                } label: {
                    PacketRow(packet: packet, start: store.packets.first?.timestamp)
                }
            }
            .listStyle(.plain)
        }
        .navigationTitle("\(filtered.count) packets")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { applyFilter() }
    }

    private var filterBar: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: "line.3.horizontal.decrease.circle")
                    .foregroundStyle(.secondary)
                TextField("tcp.port == 443 and not dns", text: $filterText)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.body.monospaced())
                    .onSubmit(applyFilter)
                if !filterText.isEmpty {
                    Button {
                        filterText = ""
                        applyFilter()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                }
            }
            if let filterError {
                Text(filterError).font(.caption).foregroundStyle(.red)
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(.bar)
    }

    private func applyFilter() {
        guard !filterText.trimmingCharacters(in: .whitespaces).isEmpty else {
            filtered = store.packets
            filterError = nil
            return
        }
        do {
            let filter = try PacketFilter(filterText)
            filtered = filter.apply(to: store.packets)
            filterError = nil
        } catch {
            // Show every packet rather than none: an empty list looks like a
            // capture problem, and the mistake is in the filter.
            filtered = store.packets
            filterError = error.localizedDescription
        }
    }
}

struct PacketRow: View {
    let packet: DecodedPacket
    let start: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(offset).font(.caption.monospaced()).foregroundStyle(.secondary)
                Text(packet.protocolName)
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Color.accentColor.opacity(0.15))
                    .clipShape(RoundedRectangle(cornerRadius: 3))
                if let vlan = packet.vlan {
                    Text("VLAN \(vlan)").font(.caption2).foregroundStyle(.secondary)
                }
                Spacer()
                Text("\(packet.length) B").font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Text("\(packet.source) → \(packet.destination)")
                .font(.callout.monospaced())
                .lineLimit(1)
            Text(packet.summary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(.vertical, 2)
    }

    /// Seconds since the first packet, which is what anyone reading a capture
    /// actually wants - absolute wall-clock time is never the question.
    private var offset: String {
        guard let start else { return "" }
        return String(format: "%7.3f", packet.timestamp.timeIntervalSince(start))
    }
}

struct PacketDetailView: View {
    let packet: DecodedPacket
    @EnvironmentObject private var store: AppStore

    var body: some View {
        List {
            Section("Frame") {
                FactRow(label: "Number", value: "#\(packet.id)")
                FactRow(label: "Time", value: packet.timestamp.formatted(date: .omitted,
                                                                        time: .standard))
                FactRow(label: "Length", value: "\(packet.length) B")
                if packet.capturedLength < packet.length {
                    FactRow(label: "Captured",
                            value: "\(packet.capturedLength) B (snaplen cut it)")
                }
                FactRow(label: "Layers", value: packet.layers.joined(separator: " / "))
            }

            Section("Addresses") {
                if let mac = packet.sourceMAC {
                    FactRow(label: "Source MAC", value: mac.description, monospaced: true)
                }
                if let mac = packet.destinationMAC {
                    FactRow(label: "Destination MAC", value: mac.description, monospaced: true)
                }
                if !packet.source.isEmpty {
                    FactRow(label: "Source", value: packet.source, monospaced: true)
                }
                if !packet.destination.isEmpty {
                    FactRow(label: "Destination", value: packet.destination, monospaced: true)
                }
                if let port = packet.sourcePort {
                    FactRow(label: "Source port", value: "\(port)")
                }
                if let port = packet.destinationPort {
                    FactRow(label: "Destination port", value: "\(port)")
                }
            }

            if let tcp = packet.tcp {
                Section("TCP") {
                    FactRow(label: "Flags", value: tcp.flagNames, monospaced: true)
                    FactRow(label: "Sequence", value: "\(tcp.sequence)")
                    FactRow(label: "Acknowledgement", value: "\(tcp.acknowledgement)")
                    FactRow(label: "Window", value: "\(tcp.window)")
                    FactRow(label: "Payload", value: "\(tcp.payloadLength) B")
                }
            }

            if let dns = packet.dns {
                Section("DNS") {
                    FactRow(label: "Transaction", value: "0x\(String(dns.id, radix: 16))")
                    FactRow(label: "Kind", value: dns.isResponse ? "response" : "query")
                    FactRow(label: "Result", value: dns.responseCodeName)
                    ForEach(dns.questions.indices, id: \.self) { index in
                        FactRow(label: dns.questions[index].typeName,
                                value: dns.questions[index].name, monospaced: true)
                    }
                }
            }

            if let wireless = packet.wireless {
                Section("802.11") {
                    FactRow(label: "Type", value: wireless.kind.rawValue)
                    if let ssid = wireless.ssid {
                        FactRow(label: "SSID",
                                value: ssid.isEmpty ? "(broadcast)" : ssid)
                    }
                    if let bssid = wireless.bssid {
                        FactRow(label: "BSSID", value: bssid.description, monospaced: true)
                    }
                    FactRow(label: "Retry", value: wireless.isRetry ? "yes" : "no")
                }
            }

            if let radio = packet.radio {
                Section("Radio") {
                    if let signal = radio.signalDBM {
                        FactRow(label: "Signal", value: "\(signal) dBm")
                    }
                    if let noise = radio.noiseDBM {
                        FactRow(label: "Noise", value: "\(noise) dBm")
                    }
                    if let snr = radio.snr { FactRow(label: "SNR", value: "\(snr) dB") }
                    if let channel = radio.channelMHz {
                        FactRow(label: "Channel", value: "\(channel) MHz")
                    }
                }
            }

            if let key = packet.streamKey {
                Section {
                    NavigationLink {
                        FollowStreamView(streamKey: key)
                    } label: {
                        Label("Follow this stream", systemImage: "text.alignleft")
                    }
                }
            }
        }
        .navigationTitle("Packet #\(packet.id)")
        .navigationBarTitleDisplayMode(.inline)
    }
}
