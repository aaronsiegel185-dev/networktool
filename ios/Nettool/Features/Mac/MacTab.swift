import SwiftUI
import NettoolKit

/// Pairing with a Mac, and using its radios and wires.
struct MacTab: View {
    @EnvironmentObject private var store: AppStore
    @StateObject private var browser = MacBrowser()
    @State private var pairingText = ""
    @State private var hello: MacHello?
    @State private var error: String?
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            List {
                if let peer = store.pairedPeer {
                    pairedSection(peer)
                } else {
                    discoverySection
                    pairingSection
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red).font(.callout) }
                }
            }
            .navigationTitle("Mac")
            .onAppear { browser.start() }
            .onDisappear { browser.stop() }
        }
    }

    // --- paired ----------------------------------------------------------

    @ViewBuilder
    private func pairedSection(_ peer: MacPeer) -> some View {
        Section("Paired") {
            FactRow(label: "Host", value: peer.host, monospaced: true)
            FactRow(label: "Port", value: "\(peer.port)")
            if let hello {
                FactRow(label: "nettool", value: hello.version)
                FactRow(label: "Platform", value: hello.platform)
                FactRow(label: "Capture",
                        value: hello.capabilities.capture ? "available" : "not available")
            }
            Button("Check connection") { Task { await check(peer) } }
                .disabled(isWorking)
        }

        Section {
            NavigationLink { RemoteCaptureView() } label: {
                Label("Capture on the Mac", systemImage: "waveform.path")
            }
            NavigationLink { RemoteCaptureListView() } label: {
                Label("Captures on the Mac", systemImage: "folder")
            }
        } footer: {
            Text("iOS will not give any app a raw socket, so the phone cannot "
                 + "capture packets itself at any tier. The Mac does it and hands "
                 + "the file back, and everything after that runs here.")
        }

        Section {
            Button("Unpair", role: .destructive) { Task { await store.unpair() } }
        }
    }

    // --- unpaired --------------------------------------------------------

    private var discoverySection: some View {
        Section {
            if browser.peers.isEmpty {
                HStack {
                    if browser.isSearching { ProgressView().controlSize(.small) }
                    Text(browser.isSearching
                         ? "Looking for Macs running nettool serve..."
                         : "Not searching")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } else {
                ForEach(browser.peers) { peer in
                    Button {
                        pairingText = "nettool://\(peer.host):\(peer.port)/?token="
                    } label: {
                        VStack(alignment: .leading) {
                            Text(peer.name)
                            Text("\(peer.host):\(peer.port)")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        } header: {
            Label("On this network", systemImage: "bonjour")
        } footer: {
            Text("On the Mac, run:  nettool serve --lan")
        }
    }

    private var pairingSection: some View {
        Section {
            TextField("nettool://192.168.1.10:8765/?token=...", text: $pairingText)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.caption.monospaced())
            Button("Pair") { Task { await pair() } }
                .disabled(pairingText.isEmpty || isWorking)
        } header: {
            Text("Pairing link")
        } footer: {
            Text("`nettool serve --lan` prints this line. Paste it whole - the "
                 + "token is in it, so there is nothing to type by hand.")
        }
    }

    private func pair() async {
        guard let (peer, token) = MacLink.peer(fromPairingURL: pairingText) else {
            error = "That is not a pairing link. It should look like "
                  + "nettool://host:8765/?token=..."
            return
        }
        isWorking = true
        defer { isWorking = false }
        do {
            // Prove it answers before storing anything, so a typo fails here
            // rather than on every screen afterwards.
            hello = try await store.macLink.hello(at: peer)
            await store.pair(peer: peer, token: token)
            error = nil
        } catch {
            self.error = "Could not reach that Mac: \(error.localizedDescription)"
        }
    }

    private func check(_ peer: MacPeer) async {
        isWorking = true
        defer { isWorking = false }
        do {
            hello = try await store.macLink.hello(at: peer)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct RemoteCaptureView: View {
    @EnvironmentObject private var store: AppStore
    @State private var interface = ""
    @State private var seconds = 10.0
    @State private var filter = ""
    @State private var running = false
    @State private var error: String?
    @State private var done: String?

    var body: some View {
        List {
            Section {
                TextField("interface (blank for the default)", text: $interface)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                VStack(alignment: .leading) {
                    Text("Duration: \(Int(seconds)) s")
                    Slider(value: $seconds, in: 2...120, step: 1)
                }
                TextField("BPF filter, e.g. port 53", text: $filter)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.body.monospaced())
                Button(running ? "Capturing..." : "Capture and open") {
                    Task { await run() }
                }
                .disabled(running)
            } footer: {
                Text("The Mac captures, the file comes back here, and it opens in "
                     + "the Captures tab - decoded on the phone.")
            }

            if let done {
                Section { Label(done, systemImage: "checkmark.circle").foregroundStyle(.green) }
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Remote capture")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func run() async {
        running = true
        error = nil
        done = nil
        defer { running = false }
        do {
            let file = try await store.macLink.capture(
                interface: interface.isEmpty ? nil : interface,
                seconds: Int(seconds),
                filter: filter.isEmpty ? nil : filter)
            await store.adopt(file, named: "from-mac.pcap")
            done = "\(file.packets.count) packets - open the Captures tab"
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct RemoteCaptureListView: View {
    @EnvironmentObject private var store: AppStore
    @State private var listing: CaptureListing?
    @State private var error: String?
    @State private var loading: String?

    var body: some View {
        List {
            if let listing {
                Section(listing.directory) {
                    ForEach(listing.captures) { entry in
                        Button {
                            Task { await open(entry) }
                        } label: {
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(entry.name)
                                    Text(entry.bytes.asBytes)
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if loading == entry.name {
                                    ProgressView().controlSize(.small)
                                } else {
                                    Image(systemName: "arrow.down.circle")
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                    if listing.captures.isEmpty {
                        Text("No captures on the Mac yet.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
            } else if error == nil {
                ProgressView()
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("On the Mac")
        .navigationBarTitleDisplayMode(.inline)
        .task { await refresh() }
        .refreshable { await refresh() }
    }

    private func refresh() async {
        do {
            listing = try await store.macLink.captures()
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func open(_ entry: CaptureListing.Entry) async {
        loading = entry.name
        defer { loading = nil }
        do {
            let data = try await store.macLink.download(file: entry.name)
            let file = try CaptureFile.read(data: data)
            await store.adopt(file, named: entry.name)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}
