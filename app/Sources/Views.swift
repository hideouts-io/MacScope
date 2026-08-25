import AppKit
import SwiftUI

struct DashboardView: View {
    @ObservedObject var coordinator: ScanCoordinator

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MacScopeStyle.contentSpacing) {
                SectionHeading(
                    eyebrow: "Security posture",
                    title: coordinator.scanDocument == nil ? "Know what your Mac is telling you" : "Scan overview",
                    subtitle: coordinator.scanDocument == nil
                        ? "MacScope combines native macOS evidence with focused open-source instruments, then explains the findings and the gaps."
                        : "Every summary below links back to a finding, instrument, or explicit coverage record."
                )

                if let document = coordinator.scanDocument {
                    completedDashboard(document)
                } else {
                    welcomeCard
                }
            }
            .frame(maxWidth: MacScopeStyle.maximumReadableWidth, alignment: .leading)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("Dashboard")
    }

    private var welcomeCard: some View {
        HStack(spacing: 30) {
            Image("MacScopeLogo")
                .resizable()
                .scaledToFit()
                .frame(width: 190, height: 190)
                .accessibilityLabel("MacScope logo")
            VStack(alignment: .leading, spacing: 14) {
                Text("Evidence first. Read only. Local by default.")
                    .font(.title2.weight(.semibold))
                Text("Run a standard scan without administrator access. MacScope will inventory native controls, Apple security updates, persistence, listeners, installed software, and known package vulnerabilities. It never uploads your results silently.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Start Standard Scan") {
                        coordinator.startStandardScan()
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .accessibilityIdentifier("scan.start.dashboard")
                    Button("Review Scan Setup") {
                        coordinator.selectedSection = .newScan
                    }
                    .controlSize(.large)
                }
                Label("Locally downloaded iCloud files are eligible; cloud-only items are not downloaded.", systemImage: "icloud.and.arrow.down")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .macScopeCard()
    }

    @ViewBuilder
    private func completedDashboard(_ document: ScanDocument) -> some View {
        HStack(spacing: 12) {
            SummaryMetric(title: "Findings", value: "\(document.findings.count)", detail: "Detected records", color: .blue, symbol: "list.bullet.rectangle")
            SummaryMetric(title: "High priority", value: "\(highPriorityCount(document))", detail: "Critical or high", color: .red, symbol: "exclamationmark.triangle.fill")
            SummaryMetric(title: "Known exploited", value: "\(knownExploitedCount(document))", detail: "CISA KEV references", color: .purple, symbol: "bolt.shield.fill")
            SummaryMetric(title: "Coverage gaps", value: "\(gapCount(document))", detail: "Partial or not scanned", color: .orange, symbol: "scope")
        }

        HStack(alignment: .top, spacing: MacScopeStyle.contentSpacing) {
            VStack(alignment: .leading, spacing: 12) {
                Text("This Mac")
                    .font(.headline)
                LabeledContent("Device", value: document.host.modelID ?? document.host.hostname)
                LabeledContent("macOS", value: [document.host.macOSVersion, document.host.macOSBuild].compactMap { $0 }.joined(separator: " · "))
                LabeledContent("Chip", value: document.host.chip ?? document.host.architecture)
                LabeledContent("Run status", value: displayName(document.status))
                LabeledContent("Privilege", value: document.privilege.granted ? "Enhanced read-only" : "Standard")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .macScopeCard()

            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Needs attention")
                        .font(.headline)
                    Spacer()
                    Button("View all") { coordinator.selectedSection = .attention }
                        .buttonStyle(.link)
                }
                if coordinator.attentionFindings.isEmpty {
                    Label("No high-priority records in this scan", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                } else {
                    ForEach(coordinator.attentionFindings.prefix(4)) { finding in
                        CompactFindingRow(finding: finding)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .macScopeCard()
        }

        HStack {
            Label("No score is shown: missing coverage must not look like a clean bill of health.", systemImage: "info.circle")
                .font(.callout)
                .foregroundStyle(.secondary)
            Spacer()
            Button("Show Scan Folder") { coordinator.revealOutput() }
                .disabled(coordinator.outputDirectory == nil)
        }
        .macScopeCard()
    }
}

struct SummaryMetric: View {
    let title: String
    let value: String
    let detail: String
    let color: Color
    let symbol: String

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: symbol)
                    .foregroundStyle(color)
                Spacer()
                Text(value)
                    .font(.system(size: 27, weight: .bold, design: .rounded))
                    .monospacedDigit()
            }
            Text(title)
                .font(.headline)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .macScopeCard()
    }
}

struct NewScanView: View {
    @ObservedObject var coordinator: ScanCoordinator

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MacScopeStyle.contentSpacing) {
                SectionHeading(
                    eyebrow: "New scan",
                    title: "Choose exactly what MacScope may assess",
                    subtitle: "The first app release keeps remediation and collection read-only. Exclusions are visible before the scan begins."
                )

                HStack(alignment: .top, spacing: 14) {
                    scanChoice(
                        title: "Standard",
                        subtitle: "Recommended",
                        description: "No administrator authorization. Covers native controls, public Apple security data, persistence, listeners, software inventory, and packages available to your user.",
                        symbol: "checkmark.shield.fill",
                        selected: true
                    )
                    scanChoice(
                        title: "Enhanced Read-Only",
                        subtitle: "Planned",
                        description: "Adds narrowly scoped PF and Remote Login evidence through a signed helper. The app will never collect a password itself.",
                        symbol: "lock.shield",
                        selected: false
                    )
                }

                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Excluded files and directories")
                                .font(.headline)
                            Text("OneDrive locations are detected and excluded by default. iCloud Drive is not excluded.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Add File…") {
                            if let url = chooseFile() { coordinator.addExclusion(url) }
                        }
                        .accessibilityIdentifier("scan.exclude.file")
                        Button("Add Folder…") {
                            if let url = chooseDirectory() { coordinator.addExclusion(url) }
                        }
                        .accessibilityIdentifier("scan.exclude.folder")
                    }

                    if coordinator.excludedPaths.isEmpty {
                        Text("No exclusions selected")
                            .foregroundStyle(.secondary)
                            .padding(.vertical, 8)
                    } else {
                        ForEach(coordinator.excludedPaths, id: \.self) { path in
                            HStack(spacing: 10) {
                                Image(systemName: "folder.badge.minus")
                                    .foregroundStyle(.orange)
                                Text(path)
                                    .font(.callout.monospaced())
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                Spacer()
                                Button {
                                    coordinator.removeExclusion(path)
                                } label: {
                                    Image(systemName: "xmark.circle.fill")
                                }
                                .buttonStyle(.plain)
                                .foregroundStyle(.secondary)
                                .accessibilityLabel("Remove exclusion \(path)")
                            }
                            .padding(.vertical, 3)
                        }
                    }
                }
                .macScopeCard()

                HStack(alignment: .top, spacing: 14) {
                    scopeCard(symbol: "icloud", title: "iCloud behavior", text: "MacScope can inspect files that are already present locally. It does not intentionally hydrate or download cloud-only placeholders.")
                    scopeCard(symbol: "externaldrive", title: "Local evidence", text: "Results, raw events, hashes, and reports stay under ~/Library/Application Support/MacScope unless you explicitly export them.")
                    scopeCard(symbol: "network", title: "Network use", text: "SOFA security data and the Grype vulnerability database may require network access. Coverage records identify failures.")
                }

                HStack {
                    Label("Large archives can be added above as exclusions without removing the rest of their directory.", systemImage: "archivebox")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Start Standard Scan") {
                        coordinator.startStandardScan()
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(coordinator.phase.isActive)
                    .accessibilityIdentifier("scan.start.setup")
                }
                .macScopeCard()
            }
            .frame(maxWidth: MacScopeStyle.maximumReadableWidth, alignment: .leading)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("New Scan")
    }

    private func scanChoice(title: String, subtitle: String, description: String, symbol: String, selected: Bool) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: symbol)
                    .font(.title2)
                    .foregroundStyle(selected ? .red : .secondary)
                Spacer()
                StatusPill(text: subtitle, color: selected ? .green : .secondary, symbol: selected ? "checkmark" : "clock")
            }
            Text(title)
                .font(.title3.weight(.semibold))
            Text(description)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, minHeight: 140, alignment: .topLeading)
        .macScopeCard()
        .opacity(selected ? 1 : 0.72)
    }

    private func scopeCard(symbol: String, title: String, text: String) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Image(systemName: symbol)
                .font(.title2)
                .foregroundStyle(.red)
            Text(title).font(.headline)
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .macScopeCard()
    }
}

struct LiveActivityView: View {
    @ObservedObject var coordinator: ScanCoordinator
    @State private var search = ""
    @State private var errorsOnly = false

    private var visibleActivities: [ActivityEntry] {
        coordinator.activities.filter { entry in
            let matchesError = !errorsOnly || entry.isError
            let trimmedSearch = search.trimmingCharacters(in: .whitespacesAndNewlines)
            let matchesSearch = trimmedSearch.isEmpty
                || entry.summary.localizedCaseInsensitiveContains(trimmedSearch)
                || entry.detail.localizedCaseInsensitiveContains(trimmedSearch)
                || entry.collectorID.localizedCaseInsensitiveContains(trimmedSearch)
            return matchesError && matchesSearch
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .top) {
                    SectionHeading(
                        eyebrow: "Live activity",
                        title: coordinator.phase.label,
                        subtitle: coordinator.progressMessage
                    )
                    Spacer()
                    if coordinator.phase.isActive {
                        Button("Cancel Scan", role: .destructive) { coordinator.cancelScan() }
                            .accessibilityIdentifier("scan.cancel.activity")
                    } else if coordinator.outputDirectory != nil {
                        Button("Show Scan Folder") { coordinator.revealOutput() }
                    }
                }
                HStack(spacing: 14) {
                    ProgressView(value: Double(coordinator.progressPercent), total: 100)
                        .tint(.red)
                    Text("\(coordinator.progressPercent)%")
                        .font(.headline.monospacedDigit())
                    Text(formatDuration(coordinator.elapsedSeconds))
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)
                    StatusPill(text: coordinator.activeCollector, color: .red, symbol: "waveform.path.ecg")
                }
            }
            .padding(24)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 10) {
                    ForEach(coordinator.instruments) { instrument in
                        InstrumentStatusCard(instrument: instrument)
                    }
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 18)
            }

            VStack(spacing: 0) {
                HStack {
                    Image(systemName: "terminal")
                    Text("Command & output stream")
                        .font(.headline)
                    StatusPill(text: "Private host data", color: .orange, symbol: "hand.raised.fill")
                    Spacer()
                    Toggle("Errors only", isOn: $errorsOnly)
                        .toggleStyle(.checkbox)
                    TextField("Filter activity", text: $search)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 220)
                        .accessibilityIdentifier("activity.search")
                }
                .padding(12)
                .background(.bar)

                if visibleActivities.isEmpty {
                    ContentUnavailableView("No activity yet", systemImage: "terminal", description: Text("Start a scan to see each instrument, command, and output event in real time."))
                } else {
                    List(visibleActivities) { entry in
                        ActivityRow(entry: entry)
                    }
                    .listStyle(.inset)
                }
            }
            .overlay { Rectangle().stroke(.separator, lineWidth: 1) }
        }
        .navigationTitle("Live Activity")
    }
}

struct InstrumentStatusCard: View {
    let instrument: InstrumentActivity

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                Circle().fill(stateColor).frame(width: 8, height: 8)
                Text(instrument.name).font(.subheadline.weight(.semibold))
            }
            Text(displayName(instrument.state.rawValue))
                .font(.caption.weight(.medium))
                .foregroundStyle(stateColor)
            Text(instrument.detail)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .frame(width: 185, height: 76, alignment: .topLeading)
        .macScopeCard()
    }

    private var stateColor: Color {
        switch instrument.state {
        case .queued: .secondary
        case .running: .orange
        case .completed: .green
        case .failed: .red
        }
    }
}

struct ActivityRow: View {
    let entry: ActivityEntry

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: entry.isError ? "exclamationmark.circle.fill" : icon)
                .foregroundStyle(entry.isError ? .red : .secondary)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(entry.collectorID)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.red)
                    Text(entry.kind)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if entry.isPrivate {
                        Image(systemName: "hand.raised.fill")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                            .accessibilityLabel("May contain private host data")
                    }
                    Spacer()
                    Text(shortTimestamp(entry.timestamp))
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.tertiary)
                }
                Text(entry.summary)
                    .font(.callout.weight(.medium))
                if !entry.detail.isEmpty {
                    Text(entry.detail)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .lineLimit(8)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private var icon: String {
        switch entry.kind {
        case "Command": "terminal"
        case "STDOUT", "STDERR": "text.alignleft"
        case "Result": "checkmark.circle"
        default: "circle.fill"
        }
    }
}

struct AttentionView: View {
    @ObservedObject var coordinator: ScanCoordinator

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MacScopeStyle.contentSpacing) {
                SectionHeading(
                    eyebrow: "Attention",
                    title: "Results that deserve a closer look",
                    subtitle: "An anomaly or failed control is an unexpected observation—not proof that the Mac is compromised. Verify evidence and context before acting."
                )
                if coordinator.scanDocument == nil {
                    EmptyState(symbol: "exclamationmark.triangle", title: "No completed scan", message: "Complete a scan to collect high-severity findings, coverage gaps, tool errors, and threat indicators here.")
                } else if coordinator.attentionFindings.isEmpty {
                    EmptyState(symbol: "checkmark.seal", title: "No priority records", message: "This scan contains no critical, high, coverage-gap, tool-error, or threat-indicator findings. Review Coverage before drawing conclusions.")
                } else {
                    ForEach(coordinator.attentionFindings) { finding in
                        FindingDisclosure(finding: finding, coordinator: coordinator)
                    }
                }
            }
            .frame(maxWidth: MacScopeStyle.maximumReadableWidth, alignment: .leading)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("Attention")
    }
}

struct FindingsView: View {
    @ObservedObject var coordinator: ScanCoordinator

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                SectionHeading(
                    eyebrow: "Evidence-backed results",
                    title: "Findings",
                    subtitle: "Read what was observed, why it matters, its limits, supporting sources, and ordered remediation guidance."
                )
                HStack {
                    TextField("Search title, description, or rule ID", text: $coordinator.findingSearch)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("findings.search")
                    Picker("Severity", selection: $coordinator.findingSeverity) {
                        Text("All severities").tag("all")
                        Text("Critical").tag("critical")
                        Text("High").tag("high")
                        Text("Medium").tag("medium")
                        Text("Low").tag("low")
                        Text("Info").tag("info")
                    }
                    .frame(width: 180)
                }
            }
            .padding(24)

            if coordinator.scanDocument == nil {
                EmptyState(symbol: "list.bullet.rectangle", title: "No findings loaded", message: "Complete a scan to read findings and remediation guidance.")
                    .padding(24)
            } else if coordinator.filteredFindings.isEmpty {
                EmptyState(symbol: "magnifyingglass", title: "No matching findings", message: "Change the search text or severity filter.")
                    .padding(24)
            } else {
                List(coordinator.filteredFindings) { finding in
                    FindingDisclosure(finding: finding, coordinator: coordinator)
                        .listRowSeparator(.hidden)
                        .listRowInsets(EdgeInsets(top: 6, leading: 20, bottom: 6, trailing: 20))
                }
                .listStyle(.plain)
            }
        }
        .navigationTitle("Findings")
    }
}

struct FindingDisclosure: View {
    let finding: FindingRecord
    @ObservedObject var coordinator: ScanCoordinator
    @State private var expanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 16) {
                Text(finding.description)
                    .textSelection(.enabled)

                if !finding.vulnerabilities.isEmpty {
                    detailSection("Vulnerabilities") {
                        ForEach(finding.vulnerabilities) { vulnerability in
                            HStack {
                                Text(vulnerability.id).font(.callout.monospaced().weight(.semibold))
                                if let cvss = vulnerability.cvss { StatusPill(text: "CVSS \(cvss.formatted(.number.precision(.fractionLength(1))))", color: .orange, symbol: "chart.bar") }
                                if vulnerability.knownExploited { StatusPill(text: "Known exploited", color: .red, symbol: "bolt.fill") }
                                Spacer()
                                Button("Source") { coordinator.openReference(vulnerability.url) }
                                    .buttonStyle(.link)
                            }
                        }
                    }
                }

                detailSection("Remediation") {
                    Text(finding.remediation.summary).font(.callout.weight(.medium))
                    ForEach(Array(finding.remediation.steps.enumerated()), id: \.offset) { index, step in
                        HStack(alignment: .top, spacing: 9) {
                            Text("\(index + 1)")
                                .font(.caption.bold())
                                .foregroundStyle(.white)
                                .frame(width: 21, height: 21)
                                .background(.red, in: Circle())
                            Text(step).textSelection(.enabled)
                        }
                    }
                    HStack {
                        if finding.remediation.requiresAdmin { StatusPill(text: "Administrator required", color: .orange, symbol: "lock.fill") }
                        if finding.remediation.requiresRestart { StatusPill(text: "Restart required", color: .blue, symbol: "restart") }
                    }
                }

                detailSection("Evidence and limits") {
                    Text("Confidence: \(displayName(finding.confidence)) · Category: \(displayName(finding.category))")
                        .font(.callout)
                    Text("Rules: \(finding.sources.map { "\($0.toolID)/\($0.ruleID)" }.joined(separator: ", "))")
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                    Text("Evidence IDs: \(finding.evidenceIDs.joined(separator: ", "))")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    Text("This record describes what the cited rules observed. It does not, by itself, establish exploitation, intent, or compromise.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.top, 14)
        } label: {
            HStack(spacing: 12) {
                SeverityBadge(severity: finding.severity)
                VStack(alignment: .leading, spacing: 3) {
                    Text(finding.title).font(.headline)
                    Text("\(displayName(finding.category)) · \(finding.id)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if finding.vulnerabilities.contains(where: \.knownExploited) {
                    StatusPill(text: "KEV", color: .red, symbol: "bolt.fill")
                }
            }
        }
        .macScopeCard()
        .accessibilityIdentifier("finding.\(finding.id)")
    }

    private func detailSection<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title).font(.subheadline.weight(.semibold))
            content()
        }
    }
}

struct SeverityBadge: View {
    let severity: String

    var body: some View {
        Text(displayName(severity))
            .font(.caption2.bold())
            .foregroundStyle(.white)
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(MacScopeStyle.severityColor(severity), in: Capsule())
            .frame(width: 72)
    }
}

struct CompactFindingRow: View {
    let finding: FindingRecord

    var body: some View {
        HStack(spacing: 9) {
            Circle().fill(MacScopeStyle.severityColor(finding.severity)).frame(width: 8, height: 8)
            Text(finding.title).lineLimit(1)
            Spacer()
            Text(displayName(finding.severity)).font(.caption).foregroundStyle(.secondary)
        }
    }
}

struct InstrumentsView: View {
    @ObservedObject var coordinator: ScanCoordinator

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MacScopeStyle.contentSpacing) {
                SectionHeading(
                    eyebrow: "Provenance",
                    title: "Instruments",
                    subtitle: "MacScope preserves tool identity, version, origin, executable hashes, and the results each instrument contributed."
                )
                if let tools = coordinator.scanDocument?.tools, !tools.isEmpty {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 320), spacing: 14)], spacing: 14) {
                        ForEach(tools) { tool in
                            ToolCard(tool: tool)
                        }
                    }
                } else {
                    ForEach(coordinator.instruments) { instrument in
                        InstrumentStatusCard(instrument: instrument)
                    }
                }
            }
            .frame(maxWidth: MacScopeStyle.maximumReadableWidth, alignment: .leading)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("Instruments")
    }
}

struct ToolCard: View {
    let tool: ToolRecord

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack {
                Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                Text(tool.name).font(.headline)
                Spacer()
                StatusPill(text: displayName(tool.kind), color: .blue, symbol: "wrench")
            }
            LabeledContent("Version", value: tool.version)
            if let origin = tool.origin {
                Text(origin).font(.caption).foregroundStyle(.secondary).textSelection(.enabled).lineLimit(2)
            }
            if let executable = tool.executable {
                VStack(alignment: .leading, spacing: 3) {
                    Text(executable.path).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                    Text(executable.sha256).font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .macScopeCard()
    }
}

struct CoverageView: View {
    @ObservedObject var coordinator: ScanCoordinator

    var body: some View {
        VStack(spacing: 0) {
            SectionHeading(
                eyebrow: "Scope and limits",
                title: "Coverage",
                subtitle: "A pass means evidence was observed. Not scanned, partial, and failed remain unknown—not clean."
            )
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)

            if let coverage = coordinator.scanDocument?.coverage, !coverage.isEmpty {
                Table(coverage) {
                    TableColumn("Status") { record in
                        StatusPill(text: displayName(record.status), color: MacScopeStyle.coverageColor(record.status), symbol: coverageSymbol(record.status))
                    }
                    .width(min: 120, ideal: 140)
                    TableColumn("Area") { record in Text(displayName(record.area)) }
                        .width(min: 150, ideal: 180)
                    TableColumn("Instrument") { record in Text(record.collectorID).font(.callout.monospaced()) }
                        .width(min: 100, ideal: 120)
                    TableColumn("Target") { record in Text(record.target).lineLimit(2) }
                    TableColumn("Reason") { record in Text(record.reason ?? "Observed without a reported gap").foregroundStyle(.secondary).lineLimit(3) }
                }
            } else {
                EmptyState(symbol: "scope", title: "No coverage records loaded", message: "Complete a scan to see assessed targets, required permissions, exclusions, failures, and unknown areas.")
                    .padding(24)
            }
        }
        .navigationTitle("Coverage")
    }
}

struct HistoryView: View {
    @ObservedObject var coordinator: ScanCoordinator

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MacScopeStyle.contentSpacing) {
                SectionHeading(
                    eyebrow: "Local evidence",
                    title: "Scan history",
                    subtitle: "MacScope stores scans locally. A durable indexed comparison view is the next roadmap milestone; historical scan documents remain untouched."
                )
                if let document = coordinator.scanDocument, let output = coordinator.outputDirectory {
                    VStack(alignment: .leading, spacing: 11) {
                        HStack {
                            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                            Text(document.runID).font(.headline.monospaced())
                            Spacer()
                            StatusPill(text: displayName(document.status), color: .green, symbol: "checkmark")
                        }
                        Text(output.path).font(.callout.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                        Text("\(document.findings.count) findings · \(document.coverage.count) coverage records · \(document.tools.count) instruments")
                            .font(.callout)
                        Button("Show Scan Folder") { coordinator.revealOutput() }
                    }
                    .macScopeCard()
                } else {
                    EmptyState(symbol: "clock.arrow.circlepath", title: "No scan in this session", message: "Completed evidence stays in ~/Library/Application Support/MacScope/Scans.")
                }
            }
            .frame(maxWidth: MacScopeStyle.maximumReadableWidth, alignment: .leading)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("History")
    }
}

struct FindingsLibraryView: View {
    private let categories: [(String, String, String)] = [
        ("OS vulnerabilities", "apple.logo", "Apple security releases, CVEs, known-exploited status, and whether the installed macOS build is current."),
        ("Software vulnerabilities", "shippingbox", "Packages discovered by Syft and matched against the pinned Grype vulnerability database."),
        ("Security configuration", "switch.2", "Native macOS and mSCP checks such as firewall state, Gatekeeper, SIP, FileVault, and security policy."),
        ("Network exposure", "network", "Listening services and control state that may expose the Mac. Exposure is not proof of malicious access."),
        ("Persistence", "arrow.triangle.2.circlepath", "Launch agents, daemons, login items, and related mechanisms. Presence alone does not establish malicious intent."),
        ("Coverage gaps", "scope", "Targets MacScope could not inspect because of permissions, exclusions, cloud-only data, unavailable tools, or collection failure.")
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MacScopeStyle.contentSpacing) {
                SectionHeading(
                    eyebrow: "Master findings documentation",
                    title: "How MacScope interprets evidence",
                    subtitle: "This reader separates detection from interpretation. The structured rule catalog will become the single source for every supported rule, remediation, limitation, and reference."
                )
                ForEach(categories, id: \.0) { category in
                    HStack(alignment: .top, spacing: 14) {
                        Image(systemName: category.1)
                            .font(.title2)
                            .foregroundStyle(.red)
                            .frame(width: 30)
                        VStack(alignment: .leading, spacing: 5) {
                            Text(category.0).font(.headline)
                            Text(category.2).foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .macScopeCard()
                }
                Label("A finding is a rule-backed observation. It is not automatically an incident, exploit, or attribution.", systemImage: "info.circle.fill")
                    .foregroundStyle(.secondary)
                    .macScopeCard()
            }
            .frame(maxWidth: MacScopeStyle.maximumReadableWidth, alignment: .leading)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("Findings Library")
    }
}

struct SettingsView: View {
    @ObservedObject var coordinator: ScanCoordinator

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MacScopeStyle.contentSpacing) {
                SectionHeading(
                    eyebrow: "Preferences",
                    title: "Privacy and storage",
                    subtitle: "MacScope is designed for local, evidence-preserving analysis with explicit export boundaries."
                )
                VStack(alignment: .leading, spacing: 14) {
                    settingRow(symbol: "hand.raised.fill", title: "Telemetry", value: "Off", detail: "The app does not silently upload scans, commands, paths, or findings.")
                    Divider()
                    settingRow(symbol: "folder.fill", title: "Local scan storage", value: "Application Support", detail: "~/Library/Application Support/MacScope/Scans")
                    Divider()
                    settingRow(symbol: "icloud.slash", title: "Cloud-only files", value: "Not downloaded", detail: "Only iCloud items already available locally are eligible for scanning.")
                    Divider()
                    settingRow(symbol: "lock.shield.fill", title: "Automated remediation", value: "Disabled", detail: "Guidance is instructional and read-only in this release.")
                }
                .macScopeCard()
                HStack {
                    Button("Show Current Scan Folder") { coordinator.revealOutput() }
                        .disabled(coordinator.outputDirectory == nil)
                    Spacer()
                    Text("MacScope 0.2.0 · Apache-2.0")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: 820, alignment: .leading)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("Settings")
    }

    private func settingRow(symbol: String, title: String, value: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol).foregroundStyle(.red).frame(width: 22)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline)
                Text(detail).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            Text(value).foregroundStyle(.secondary)
        }
    }
}

private func chooseDirectory() -> URL? {
    let panel = NSOpenPanel()
    panel.title = "Exclude a folder from MacScope"
    panel.prompt = "Exclude Folder"
    panel.canChooseFiles = false
    panel.canChooseDirectories = true
    panel.allowsMultipleSelection = false
    panel.canCreateDirectories = false
    return panel.runModal() == .OK ? panel.url : nil
}

private func chooseFile() -> URL? {
    let panel = NSOpenPanel()
    panel.title = "Exclude a file from MacScope"
    panel.prompt = "Exclude File"
    panel.canChooseFiles = true
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    panel.canCreateDirectories = false
    return panel.runModal() == .OK ? panel.url : nil
}

private func highPriorityCount(_ document: ScanDocument) -> Int {
    document.findings.filter { ["critical", "high"].contains($0.severity) }.count
}

private func knownExploitedCount(_ document: ScanDocument) -> Int {
    document.findings.filter { finding in finding.vulnerabilities.contains(where: \.knownExploited) }.count
}

private func gapCount(_ document: ScanDocument) -> Int {
    document.coverage.filter { $0.status != "complete" }.count
}

private func shortTimestamp(_ timestamp: String) -> String {
    guard let timeSeparator = timestamp.firstIndex(of: "T") else { return timestamp }
    let timeStart = timestamp.index(after: timeSeparator)
    return String(timestamp[timeStart...].prefix(12))
}

private func coverageSymbol(_ status: String) -> String {
    switch status {
    case "complete": "checkmark.circle.fill"
    case "partial": "circle.lefthalf.filled"
    case "failed": "xmark.octagon.fill"
    default: "questionmark.circle"
    }
}
