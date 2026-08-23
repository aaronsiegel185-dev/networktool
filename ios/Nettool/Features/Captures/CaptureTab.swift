import SwiftUI
import UniformTypeIdentifiers
import NettoolKit

/// The standalone half of the app: open a capture and read it.
///
/// Everything here works with no Mac, no entitlement and no network - the file
/// can arrive by AirDrop, Files, or a share sheet from anywhere.
struct CaptureTab: View {
    @EnvironmentObject private var store: AppStore
    @State private var isImporting = false

    var body: some View {
        NavigationStack {
            Group {
                if store.isLoading {
                    ProgressView("Decoding...")
                } else if store.capture == nil {
                    EmptyCaptureView(isImporting: $isImporting)
                } else {
                    CaptureSummaryView()
                }
            }
            .navigationTitle(store.captureName.isEmpty ? "Captures" : store.captureName)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        isImporting = true
                    } label: {
                        Label("Open", systemImage: "folder")
                    }
                }
            }
            .fileImporter(isPresented: $isImporting,
                          allowedContentTypes: Self.captureTypes,
                          allowsMultipleSelection: false) { result in
                guard case let .success(urls) = result, let url = urls.first else { return }
                Task { await store.load(url: url) }
            }
            .alert("Could not read that file",
                   isPresented: .constant(store.loadError != nil)) {
                Button("OK") { store.loadError = nil }
            } message: {
                Text(store.loadError ?? "")
            }
        }
    }

    /// pcap and pcapng have no registered UTIs, so they are declared by filename
    /// extension - and `.data` is the fallback for a file whose type the system
    /// could not work out at all, which is common for AirDropped captures.
    static let captureTypes: [UTType] = [
        UTType(filenameExtension: "pcap") ?? .data,
        UTType(filenameExtension: "pcapng") ?? .data,
        UTType(filenameExtension: "cap") ?? .data,
        .data,
    ]
}

struct EmptyCaptureView: View {
    @Binding var isImporting: Bool

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text("No capture open").font(.title3.weight(.medium))
            Text("Open a .pcap or .pcapng file to read it here - conversations, "
                 + "protocol mix, TCP health and the bytes themselves.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Button("Open a capture") { isImporting = true }
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct CaptureSummaryView: View {
    @EnvironmentObject private var store: AppStore

    var body: some View {
        List {
            if let capture = store.capture, let analysis = store.analysis {
                Section("Capture") {
                    FactRow(label: "Format", value: capture.format)
                    FactRow(label: "Link type", value: capture.linkType.name)
                    FactRow(label: "Packets", value: "\(analysis.packetCount)")
                    FactRow(label: "Bytes", value: analysis.byteCount.asBytes)
                    FactRow(label: "Duration",
                            value: String(format: "%.1f s", analysis.duration))
                    FactRow(label: "Average packet",
                            value: "\(analysis.averagePacketSize) B")
                }

                Section("Findings") {
                    ForEach(analysis.findings) { FindingRow(finding: $0) }
                }

                Section {
                    NavigationLink {
                        PacketListView()
                    } label: {
                        Label("Packets (\(analysis.packetCount))",
                              systemImage: "list.bullet.rectangle")
                    }
                    NavigationLink {
                        ConversationListView(conversations: analysis.conversations)
                    } label: {
                        Label("Conversations (\(analysis.conversations.count))",
                              systemImage: "arrow.left.arrow.right")
                    }
                    NavigationLink {
                        EndpointListView(endpoints: analysis.endpoints)
                    } label: {
                        Label("Endpoints (\(analysis.endpoints.count))",
                              systemImage: "dot.radiowaves.left.and.right")
                    }
                    NavigationLink {
                        ProtocolListView(analysis: analysis)
                    } label: {
                        Label("Protocols", systemImage: "chart.pie")
                    }
                }

                Section("TCP health") {
                    FactRow(label: "Retransmissions", value: "\(analysis.retransmissions)")
                    FactRow(label: "Duplicate ACKs", value: "\(analysis.duplicateAcks)")
                    FactRow(label: "Zero windows", value: "\(analysis.zeroWindows)")
                    FactRow(label: "Resets", value: "\(analysis.resets)")
                    FactRow(label: "Unanswered SYNs", value: "\(analysis.failedHandshakes)")
                }
            }
        }
    }
}
