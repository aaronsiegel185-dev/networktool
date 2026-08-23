import SwiftUI
import NettoolKit

/// The probes the phone can run on its own - no Mac, no entitlement.
struct ToolsTab: View {
    var body: some View {
        NavigationStack {
            List {
                Section {
                    NavigationLink { PingView() } label: {
                        Label("Ping", systemImage: "wave.3.forward")
                    }
                    NavigationLink { PortScanView() } label: {
                        Label("Port scan", systemImage: "lock.open")
                    }
                } footer: {
                    Text("These run from the phone itself. iOS allows ICMP over a "
                         + "datagram socket and outbound TCP, which is all these need.")
                }
            }
            .navigationTitle("Tools")
        }
    }
}

struct PingView: View {
    @State private var host = ""
    @State private var result: PingResult?
    @State private var running = false
    @State private var error: String?
    @State private var replies: [(Int, Double?)] = []

    var body: some View {
        List {
            Section {
                HStack {
                    TextField("host or address", text: $host)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .onSubmit { Task { await run() } }
                    Button(running ? "..." : "Ping") { Task { await run() } }
                        .disabled(host.isEmpty || running)
                }
            }

            if !replies.isEmpty {
                Section("Replies") {
                    ForEach(replies.indices, id: \.self) { index in
                        let reply = replies[index]
                        HStack {
                            Text("seq \(reply.0)").font(.callout.monospaced())
                            Spacer()
                            if let rtt = reply.1 {
                                Text(String(format: "%.1f ms", rtt))
                                    .font(.callout.monospaced())
                                    .foregroundStyle(.green)
                            } else {
                                Text("timeout").font(.callout).foregroundStyle(.red)
                            }
                        }
                    }
                }
            }

            if let result {
                Section("Summary") {
                    FactRow(label: "Address", value: result.address, monospaced: true)
                    FactRow(label: "Sent / received",
                            value: "\(result.sent) / \(result.received)")
                    FactRow(label: "Loss",
                            value: String(format: "%.0f%%", result.lossPercent))
                    if let average = result.average {
                        FactRow(label: "Average",
                                value: String(format: "%.1f ms", average))
                    }
                    if let jitter = result.jitter {
                        FactRow(label: "Jitter",
                                value: String(format: "%.1f ms", jitter))
                    }
                    if let minimum = result.minimum, let maximum = result.maximum {
                        FactRow(label: "Min / max",
                                value: String(format: "%.1f / %.1f ms", minimum, maximum))
                    }
                }
            }

            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Ping")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func run() async {
        running = true
        replies = []
        result = nil
        error = nil
        defer { running = false }
        do {
            result = try await Ping().run(host: host, count: 8) { sequence, rtt in
                Task { @MainActor in replies.append((sequence, rtt)) }
            }
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct PortScanView: View {
    @State private var host = ""
    @State private var portText = "22,80,443,445,3389,8080"
    @State private var results: [PortResult] = []
    @State private var running = false

    var body: some View {
        List {
            Section {
                TextField("host or address", text: $host)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                TextField("ports", text: $portText)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.body.monospaced())
                Button(running ? "Scanning..." : "Scan") { Task { await run() } }
                    .disabled(host.isEmpty || running)
            } footer: {
                Text("A TCP connect scan, from this phone. Only scan networks you "
                     + "are responsible for.")
            }

            if !results.isEmpty {
                Section("\(results.filter(\.isOpen).count) open") {
                    ForEach(results.filter(\.isOpen)) { result in
                        HStack {
                            Text("\(result.port)").font(.callout.monospaced())
                            if let service = result.service {
                                Text(service).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(String(format: "%.0f ms", result.milliseconds))
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        .navigationTitle("Port scan")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func run() async {
        running = true
        results = []
        defer { running = false }
        let ports = Self.parsePorts(portText)
        results = await PortScanner().scan(host: host, ports: ports)
    }

    /// "22,80,8000-8010" - the same shorthand the CLI takes.
    static func parsePorts(_ text: String) -> [Int] {
        var ports: Set<Int> = []
        for piece in text.split(separator: ",") {
            let trimmed = piece.trimmingCharacters(in: .whitespaces)
            if trimmed.contains("-") {
                let bounds = trimmed.split(separator: "-")
                if bounds.count == 2, let low = Int(bounds[0]), let high = Int(bounds[1]),
                   low <= high, high - low <= 2048 {
                    ports.formUnion(low...high)
                }
            } else if let port = Int(trimmed), (1...65535).contains(port) {
                ports.insert(port)
            }
        }
        return ports.sorted()
    }
}
