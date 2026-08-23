import SwiftUI
import NettoolKit

struct ConversationListView: View {
    let conversations: [Conversation]

    var body: some View {
        List(conversations) { conversation in
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(conversation.endpointA).font(.callout.monospaced()).lineLimit(1)
                    Image(systemName: conversation.isOneSided
                          ? "arrow.right" : "arrow.left.arrow.right")
                        .font(.caption)
                        .foregroundStyle(conversation.isOneSided ? .orange : .secondary)
                    Text(conversation.endpointB).font(.callout.monospaced()).lineLimit(1)
                }
                HStack(spacing: 12) {
                    Label("\(conversation.packets)", systemImage: "shippingbox")
                    Label(conversation.bytes.asBytes, systemImage: "scalemass")
                    if conversation.duration > 0 {
                        Label(String(format: "%.0f kbit/s",
                                     conversation.bitsPerSecond / 1000),
                              systemImage: "speedometer")
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                if conversation.isOneSided {
                    Text("only ever went one way")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                }
                // The split is the useful part: a conversation that is 99% one
                // direction is a download; one that is balanced is a chat.
                DirectionBar(forward: conversation.bytesAtoB,
                             reverse: conversation.bytesBtoA)
            }
            .padding(.vertical, 2)
        }
        .navigationTitle("Conversations")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct DirectionBar: View {
    let forward: Int
    let reverse: Int

    var body: some View {
        GeometryReader { geometry in
            let total = max(1, forward + reverse)
            let width = geometry.size.width * CGFloat(forward) / CGFloat(total)
            HStack(spacing: 0) {
                Rectangle().fill(Color.accentColor).frame(width: width)
                Rectangle().fill(Color.secondary.opacity(0.35))
            }
            .clipShape(Capsule())
        }
        .frame(height: 4)
    }
}

struct EndpointListView: View {
    let endpoints: [Endpoint]

    var body: some View {
        List(endpoints) { endpoint in
            VStack(alignment: .leading, spacing: 3) {
                Text(endpoint.address).font(.callout.monospaced()).lineLimit(1)
                HStack(spacing: 12) {
                    Label("\(endpoint.packets)", systemImage: "shippingbox")
                    Label(endpoint.bytes.asBytes, systemImage: "scalemass")
                    Label("\(endpoint.peers.count) peers", systemImage: "person.2")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Endpoints")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct ProtocolListView: View {
    let analysis: Analysis

    private var rows: [(name: String, packets: Int, bytes: Int)] {
        analysis.protocolCounts
            .map { ($0.key, $0.value, analysis.protocolBytes[$0.key] ?? 0) }
            .sorted { $0.2 > $1.2 }
    }

    var body: some View {
        List(rows, id: \.name) { row in
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(row.name).font(.callout.weight(.medium))
                    Spacer()
                    Text(row.bytes.asBytes).font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
                HStack {
                    ProportionBar(fraction: Double(row.bytes)
                                  / Double(max(1, analysis.byteCount)))
                    Text(String(format: "%.1f%%",
                                Double(row.bytes) / Double(max(1, analysis.byteCount)) * 100))
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                        .frame(width: 46, alignment: .trailing)
                }
                Text("\(row.packets) packets").font(.caption2).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Protocols")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct ProportionBar: View {
    let fraction: Double

    var body: some View {
        GeometryReader { geometry in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.secondary.opacity(0.18))
                Capsule().fill(Color.accentColor)
                    .frame(width: geometry.size.width * min(1, max(0, fraction)))
            }
        }
        .frame(height: 6)
    }
}

struct FollowStreamView: View {
    let streamKey: String
    @EnvironmentObject private var store: AppStore
    @State private var stream: Stream?
    @State private var showHex = false

    var body: some View {
        Group {
            if let stream {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        side(stream.clientToServer, tint: .accentColor, label: "→")
                        side(stream.serverToClient, tint: .green, label: "←")
                    }
                    .padding()
                }
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Follow stream")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Toggle("Hex", isOn: $showHex).toggleStyle(.button)
            }
        }
        .task { rebuild() }
    }

    @ViewBuilder
    private func side(_ side: StreamSide, tint: Color, label: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("\(label) \(side.label)").font(.caption.weight(.semibold))
                    .foregroundStyle(tint)
                Spacer()
                Text(side.bytes.count.asBytes).font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            if side.bytes.isEmpty {
                Text("no payload in this direction")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text(showHex || !side.looksTextual ? hexDump(side.bytes) : side.text)
                    .font(.caption2.monospaced())
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(tint.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
        }
    }

    private func rebuild() {
        stream = FollowStream.follow(streamKey: streamKey, in: store.packets) { packet in
            // The payload range was recorded during decoding, against the
            // original frame - so find it again rather than re-decoding.
            guard let range = packet.payloadRange,
                  let original = store.capture?.packets.first(where: { $0.id == packet.id }),
                  range.lowerBound <= original.bytes.count else { return [] }
            let upper = min(range.upperBound, original.bytes.count)
            guard range.lowerBound < upper else { return [] }
            return Array(original.bytes[range.lowerBound..<upper])
        }
    }

    /// Offset, hex, ASCII - the layout everyone already reads.
    private func hexDump(_ bytes: [UInt8], limit: Int = 4096) -> String {
        var lines: [String] = []
        for start in stride(from: 0, to: min(bytes.count, limit), by: 16) {
            let chunk = Array(bytes[start..<min(start + 16, bytes.count)])
            let hex = chunk.map { String(format: "%02x", $0) }.joined(separator: " ")
            let text = String(chunk.map {
                ($0 >= 0x20 && $0 < 0x7f) ? Character(UnicodeScalar($0)) : "."
            })
            let padded = hex.padding(toLength: 47, withPad: " ", startingAt: 0)
            lines.append(String(format: "%06x  ", start) + padded + "  " + text)
        }
        if bytes.count > limit {
            lines.append("... \((bytes.count - limit).asBytes) more")
        }
        return lines.joined(separator: "\n")
    }
}
