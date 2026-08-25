import SwiftUI

struct RootView: View {
    @ObservedObject var coordinator: ScanCoordinator

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 220, ideal: 244, max: 290)
        } detail: {
            content
                .background(Color(nsColor: .windowBackgroundColor))
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if coordinator.phase.isActive {
                    Button("Cancel", role: .destructive) {
                        coordinator.cancelScan()
                    }
                    .accessibilityIdentifier("scan.cancel")
                } else {
                    Button {
                        coordinator.startStandardScan()
                    } label: { Text("New Scan") }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("scan.start.toolbar")
                }
            }
        }
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            HStack(spacing: 11) {
                Image("MacScopeLogo")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 38, height: 38)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 1) {
                    Text("MacScope")
                        .font(.headline)
                    Text("macOS security evidence")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(.horizontal, 13)
            .padding(.vertical, 14)

            List(AppSection.allCases, selection: $coordinator.selectedSection) { section in
                Label(section.title, systemImage: section.symbol)
                    .tag(section)
                    .accessibilityIdentifier("navigation.\(section.rawValue)")
            }
            .listStyle(.sidebar)

            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Circle()
                        .fill(phaseColor)
                        .frame(width: 8, height: 8)
                    Text(coordinator.phase.label)
                        .font(.caption.weight(.semibold))
                    Spacer()
                    if coordinator.phase.isActive {
                        Text(formatDuration(coordinator.elapsedSeconds))
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
                Text(coordinator.progressMessage)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                if coordinator.phase.isActive {
                    ProgressView(value: Double(coordinator.progressPercent), total: 100)
                        .tint(.red)
                        .accessibilityLabel("Scan progress")
                        .accessibilityValue("\(coordinator.progressPercent) percent")
                }
            }
            .padding(14)
            .background(.bar)
        }
    }

    @ViewBuilder
    private var content: some View {
        switch coordinator.selectedSection {
        case .dashboard:
            DashboardView(coordinator: coordinator)
        case .newScan:
            NewScanView(coordinator: coordinator)
        case .liveActivity:
            LiveActivityView(coordinator: coordinator)
        case .attention:
            AttentionView(coordinator: coordinator)
        case .findings:
            FindingsView(coordinator: coordinator)
        case .instruments:
            InstrumentsView(coordinator: coordinator)
        case .coverage:
            CoverageView(coordinator: coordinator)
        case .history:
            HistoryView(coordinator: coordinator)
        case .findingsLibrary:
            FindingsLibraryView(coordinator: coordinator)
        case .settings:
            SettingsView(coordinator: coordinator)
        }
    }

    private var phaseColor: Color {
        switch coordinator.phase {
        case .completed: .green
        case .failed: .red
        case .preparing, .running, .canceling: .orange
        case .idle: .secondary
        }
    }
}

func formatDuration(_ interval: TimeInterval) -> String {
    let seconds = max(0, Int(interval))
    return String(format: "%02d:%02d", seconds / 60, seconds % 60)
}

func displayName(_ value: String) -> String {
    value.replacingOccurrences(of: "_", with: " ").capitalized
}
