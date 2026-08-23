import SwiftUI
import NettoolKit

struct RootView: View {
    @EnvironmentObject private var store: AppStore

    var body: some View {
        TabView {
            CaptureTab()
                .tabItem { Label("Captures", systemImage: "doc.text.magnifyingglass") }
            WiFiTab()
                .tabItem { Label("Wi-Fi", systemImage: "wifi") }
            ToolsTab()
                .tabItem { Label("Tools", systemImage: "network") }
            MacTab()
                .tabItem { Label("Mac", systemImage: "desktopcomputer") }
        }
    }
}

/// Shared bits of chrome, so severity means one colour throughout.
enum Palette {
    static func color(for severity: Finding.Severity) -> Color {
        switch severity {
        case .ok: return .green
        case .info: return .blue
        case .warn: return .orange
        case .critical: return .red
        }
    }

    static func color(forSignal dbm: Double) -> Color {
        switch SignalRating(dbm: dbm) {
        case .excellent, .good: return .green
        case .fair: return .yellow
        case .weak: return .orange
        case .unusable: return .red
        }
    }
}

struct FindingRow: View {
    let finding: Finding

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(finding.severity.rawValue.uppercased())
                .font(.caption2.monospaced())
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Palette.color(for: finding.severity).opacity(0.18))
                .foregroundStyle(Palette.color(for: finding.severity))
                .clipShape(RoundedRectangle(cornerRadius: 4))
            Text(finding.message)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// A row of "label / value" facts, used on every summary screen.
struct FactRow: View {
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(monospaced ? .body.monospaced() : .body)
                .multilineTextAlignment(.trailing)
        }
    }
}

extension Int {
    /// Bytes as something readable at a glance.
    var asBytes: String {
        let units = ["B", "kB", "MB", "GB"]
        var value = Double(self)
        var unit = 0
        while value >= 1024 && unit < units.count - 1 {
            value /= 1024
            unit += 1
        }
        return unit == 0 ? "\(self) B" : String(format: "%.1f %@", value, units[unit])
    }
}
