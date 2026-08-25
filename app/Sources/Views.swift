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
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 170), spacing: 12)], spacing: 12) {
            metricButton(title: "Critical", value: severityCount(document, "critical"), detail: "Immediate review", color: .purple, symbol: "exclamationmark.octagon.fill", severity: "critical")
            metricButton(title: "High", value: severityCount(document, "high"), detail: "Priority findings", color: .red, symbol: "exclamationmark.triangle.fill", severity: "high")
            metricButton(title: "Medium", value: severityCount(document, "medium"), detail: "Review and plan", color: .orange, symbol: "exclamationmark.circle", severity: "medium")
            metricButton(title: "Low", value: severityCount(document, "low"), detail: "Lower priority", color: .yellow, symbol: "info.circle", severity: "low")
            Button {
                coordinator.findingKnownExploitedOnly = true
                coordinator.selectedSection = .findings
            } label: {
                SummaryMetric(title: "Known exploited", value: "\(knownExploitedCount(document))", detail: "CISA KEV references", color: .purple, symbol: "bolt.shield.fill")
            }
            .buttonStyle(.plain)
            Button { coordinator.selectedSection = .coverage } label: {
                SummaryMetric(title: "Coverage gaps", value: "\(gapCount(document))", detail: "Partial or not scanned", color: .orange, symbol: "scope")
            }
            .buttonStyle(.plain)
        }

        HStack(alignment: .top, spacing: MacScopeStyle.contentSpacing) {
            VStack(alignment: .leading, spacing: 12) {
                Text("This Mac")
                    .font(.headline)
                LabeledContent("Device", value: document.host.modelID ?? document.host.hostname)
                LabeledContent("macOS", value: [document.host.macOSVersion, document.host.macOSBuild].compactMap { $0 }.joined(separator: " · "))
                LabeledContent("Chip", value: document.host.chip ?? document.host.architecture)
                LabeledContent("Run status", value: displayName(document.status))
                LabeledContent("Completed", value: document.completedAt)
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

    private func metricButton(title: String, value: Int, detail: String, color: Color, symbol: String, severity: String) -> some View {
        Button {
            coordinator.findingSeverity = severity
            coordinator.selectedSection = .findings
        } label: {
            SummaryMetric(title: title, value: "\(value)", detail: detail, color: color, symbol: symbol)
        }
        .buttonStyle(.plain)
        .accessibilityHint("Opens findings filtered to \(severity) severity")
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
    @State private var profileName = ""

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

                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Reusable scan profiles")
                                .font(.headline)
                            Text("Profiles contain scope choices only. They never contain credentials.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        TextField("Profile name", text: $profileName)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 190)
                            .accessibilityIdentifier("scan.profile.name")
                        Button("Save") {
                            coordinator.saveProfile(named: profileName)
                            profileName = ""
                        }
                        .disabled(profileName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                    if coordinator.savedProfiles.isEmpty {
                        Text("No profiles saved yet")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(coordinator.savedProfiles) { profile in
                            HStack {
                                Image(systemName: "slider.horizontal.3")
                                    .foregroundStyle(.red)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(profile.name).font(.callout.weight(.medium))
                                    Text("\(profile.excludedPaths.count) exclusion(s)")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Apply") { coordinator.applyProfile(profile) }
                                Button(role: .destructive) { coordinator.deleteProfile(profile) } label: {
                                    Image(systemName: "trash")
                                }
                                .buttonStyle(.borderless)
                                .accessibilityLabel("Delete profile \(profile.name)")
                            }
                        }
                    }
                }
                .macScopeCard()

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

                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Enterprise preflight")
                                .font(.headline)
                            Text("Verifies bundled tool hashes, writable data storage, disk capacity, protected-data access, and database readiness.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        StatusPill(text: displayName(coordinator.preflightState.rawValue), color: preflightColor(coordinator.preflightState), symbol: preflightSymbol(coordinator.preflightState))
                        Button("Run Preflight") { coordinator.runPreflight() }
                            .disabled(coordinator.preflightState == .running)
                            .accessibilityIdentifier("scan.preflight")
                    }
                    if coordinator.preflightState == .running {
                        ProgressView("Verifying the application and scan environment…")
                    }
                    ForEach(coordinator.preflightChecks) { check in
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: preflightSymbol(check.state))
                                .foregroundStyle(preflightColor(check.state))
                                .frame(width: 18)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(check.title).font(.callout.weight(.semibold))
                                Text(check.detail).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                                if let guidance = check.guidance {
                                    Text(guidance).font(.caption).foregroundStyle(check.state == .failed ? .red : .secondary)
                                }
                            }
                        }
                    }
                }
                .macScopeCard()

                HStack {
                    Label("Large archives can be added above as exclusions without removing the rest of their directory.", systemImage: "archivebox")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Start Standard Scan") {
                        coordinator.startStandardScan()
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(coordinator.phase.isActive || coordinator.preflightState == .failed || coordinator.preflightState == .running)
                    .accessibilityIdentifier("scan.start.setup")
                }
                .macScopeCard()
            }
            .frame(maxWidth: MacScopeStyle.maximumReadableWidth, alignment: .leading)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("New Scan")
        .task {
            if coordinator.preflightState == .pending {
                coordinator.runPreflight()
            }
        }
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
    @State private var collectorFilter = "all"

    private var visibleActivities: [ActivityEntry] {
        coordinator.activities.filter { entry in
            let matchesError = !errorsOnly || entry.isError
            let matchesCollector = collectorFilter == "all" || entry.collectorID == collectorFilter
            let trimmedSearch = search.trimmingCharacters(in: .whitespacesAndNewlines)
            let matchesSearch = trimmedSearch.isEmpty
                || entry.summary.localizedCaseInsensitiveContains(trimmedSearch)
                || entry.detail.localizedCaseInsensitiveContains(trimmedSearch)
                || entry.collectorID.localizedCaseInsensitiveContains(trimmedSearch)
            return matchesError && matchesCollector && matchesSearch
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
                    Picker("Instrument", selection: $collectorFilter) {
                        Text("All instruments").tag("all")
                        ForEach(Array(Set(coordinator.activities.map(\.collectorID))).sorted(), id: \.self) { collector in
                            Text(collector).tag(collector)
                        }
                    }
                    .frame(width: 150)
                    TextField("Filter activity", text: $search)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 220)
                        .accessibilityIdentifier("activity.search")
                    Menu {
                        Button("Copy Visible") { copyActivity(visibleActivities) }
                        Divider()
                        Button("Save Raw…") { saveRawActivity(visibleActivities) }
                        Button("Save Redacted…") { saveRedactedActivity(visibleActivities) }
                    } label: {
                        Label("Export", systemImage: "square.and.arrow.up")
                    }
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
                if instrument.state == .running {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityLabel("Indeterminate instrument progress")
                } else {
                    Circle().fill(stateColor).frame(width: 8, height: 8)
                }
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
        case .canceled: .orange
        case .notScanned: .secondary
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
                HStack(spacing: 10) {
                    Picker("Category", selection: $coordinator.findingCategory) {
                        Text("All categories").tag("all")
                        ForEach(findingCategories(coordinator.scanDocument), id: \.self) { category in
                            Text(displayName(category)).tag(category)
                        }
                    }
                    .frame(width: 190)
                    Picker("Instrument", selection: $coordinator.findingInstrument) {
                        Text("All instruments").tag("all")
                        ForEach(findingInstruments(coordinator.scanDocument), id: \.self) { instrument in
                            Text(instrument).tag(instrument)
                        }
                    }
                    .frame(width: 175)
                    Picker("Confidence", selection: $coordinator.findingConfidence) {
                        Text("All confidence").tag("all")
                        Text("Confirmed").tag("confirmed")
                        Text("High").tag("high")
                        Text("Medium").tag("medium")
                        Text("Low").tag("low")
                    }
                    .frame(width: 175)
                    Toggle("Known exploited", isOn: $coordinator.findingKnownExploitedOnly).toggleStyle(.checkbox)
                    Toggle("Admin", isOn: $coordinator.findingRequiresAdminOnly).toggleStyle(.checkbox)
                    Toggle("Restart", isOn: $coordinator.findingRequiresRestartOnly).toggleStyle(.checkbox)
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
                    if !finding.remediation.references.isEmpty {
                        ForEach(finding.remediation.references, id: \.self) { reference in
                            Button(reference) { coordinator.openReference(reference) }
                                .buttonStyle(.link)
                                .lineLimit(1)
                        }
                    }
                    Button("Prepare verification scan") {
                        coordinator.selectedSection = .newScan
                    }
                    .help("Review scope and run a new read-only scan after remediation")
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
                    ForEach(coordinator.evidence(for: finding)) { evidence in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(evidence.summary).font(.callout.weight(.medium))
                            Text("\(evidence.collectorID) · \(evidence.id)")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                            if let artifact = evidence.artifact {
                                Text("Artifact: \(artifact.path)")
                                    .font(.caption.monospaced())
                                    .textSelection(.enabled)
                                Text("SHA-256: \(artifact.sha256)")
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }
                        }
                        .padding(9)
                        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
                    }
                }

                if !finding.affectedComponents.isEmpty {
                    detailSection("Affected components") {
                        ForEach(Array(finding.affectedComponents.enumerated()), id: \.offset) { _, component in
                            HStack {
                                Image(systemName: "cube")
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(component.name).font(.callout.weight(.medium))
                                    Text([displayName(component.kind), component.identifier, component.version, component.path].compactMap { $0 }.joined(separator: " · "))
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                        .textSelection(.enabled)
                                }
                            }
                        }
                    }
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
                    LazyVStack(spacing: 14) {
                        ForEach(tools) { tool in
                            InstrumentDetailCard(tool: tool, document: coordinator.scanDocument)
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

struct InstrumentDetailCard: View {
    let tool: ToolRecord
    let document: ScanDocument?
    @State private var expanded = false

    private var findings: [FindingRecord] {
        (document?.findings ?? []).filter { $0.sources.contains { $0.toolID == tool.id } }
    }

    private var evidence: [EvidenceRecord] {
        (document?.evidence ?? []).filter { $0.collectorID == tool.id }
    }

    private var coverage: [CoverageRecord] {
        (document?.coverage ?? []).filter { $0.collectorID == tool.id }
    }

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 20) {
                    LabeledContent("Findings", value: "\(findings.count)")
                    LabeledContent("Evidence", value: "\(evidence.count)")
                    LabeledContent("Coverage", value: "\(coverage.count)")
                }
                if let origin = tool.origin {
                    LabeledContent("Upstream origin") {
                        Text(origin).textSelection(.enabled)
                    }
                }
                if let executable = tool.executable {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Executable identity").font(.subheadline.weight(.semibold))
                        Text(executable.path).font(.caption.monospaced()).textSelection(.enabled)
                        Text(executable.sha256).font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
                if coverage.isEmpty {
                    Text("This instrument has no coverage records in the loaded scan.")
                        .foregroundStyle(.secondary)
                } else {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Assessed targets").font(.subheadline.weight(.semibold))
                        ForEach(coverage) { record in
                            HStack(alignment: .top) {
                                StatusPill(text: coveragePresentationStatus(record), color: MacScopeStyle.coverageColor(record.status), symbol: coverageSymbol(record.status))
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(record.target).font(.callout)
                                    if let reason = record.reason, !reason.isEmpty {
                                        Text(reason).font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                    }
                }
                if !findings.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Findings from this instrument").font(.subheadline.weight(.semibold))
                        ForEach(findings.prefix(8)) { finding in CompactFindingRow(finding: finding) }
                        if findings.count > 8 { Text("\(findings.count - 8) additional finding(s) are available in Findings.").font(.caption).foregroundStyle(.secondary) }
                    }
                }
                if !evidence.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Evidence and artifacts").font(.subheadline.weight(.semibold))
                        ForEach(evidence.prefix(10)) { record in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(record.summary).font(.callout)
                                Text(record.artifact?.path ?? record.id).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                            }
                        }
                    }
                }
            }
            .padding(.top, 14)
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                VStack(alignment: .leading, spacing: 2) {
                    Text(tool.name).font(.headline)
                    Text("Version \(tool.version) · \(displayName(tool.kind))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                StatusPill(text: "\(findings.count) findings", color: findings.isEmpty ? .green : .orange, symbol: findings.isEmpty ? "checkmark" : "exclamationmark.triangle")
            }
        }
        .macScopeCard()
        .accessibilityIdentifier("instrument.\(tool.id)")
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
                        StatusPill(text: coveragePresentationStatus(record), color: MacScopeStyle.coverageColor(record.status), symbol: coverageSymbol(record.status))
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
                    subtitle: "Validated scans remain untouched. Export exact JSON, an offline report, or a complete portable evidence directory only when you choose."
                )
                exportStatus
                if coordinator.history.isEmpty {
                    EmptyState(symbol: "clock.arrow.circlepath", title: "No scan in this session", message: "Completed evidence stays in ~/Library/Application Support/MacScope/Scans.")
                } else {
                    if let comparison = compareLatestScans(coordinator.history) {
                        HStack(spacing: 14) {
                            SummaryMetric(title: "New", value: "\(comparison.newCount)", detail: "Not in prior scan", color: .orange, symbol: "plus.circle")
                            SummaryMetric(title: "Persistent", value: "\(comparison.persistentCount)", detail: "Present in both", color: .blue, symbol: "equal.circle")
                            SummaryMetric(title: "Resolved", value: comparison.coverageComparable ? "\(comparison.resolvedCount)" : "—", detail: comparison.coverageComparable ? "Absent with comparable coverage" : "Coverage changed", color: .green, symbol: "checkmark.circle")
                        }
                    }
                    ForEach(coordinator.history) { item in
                        VStack(alignment: .leading, spacing: 11) {
                            HStack {
                                Image(systemName: item.document.status == "completed" ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                                    .foregroundStyle(item.document.status == "completed" ? .green : .orange)
                                Text(item.document.runID).font(.headline.monospaced())
                                Spacer()
                                StatusPill(text: displayName(item.document.status), color: item.document.status == "completed" ? .green : .orange, symbol: item.document.status == "completed" ? "checkmark" : "exclamationmark.triangle")
                                if coordinator.isPastRetention(item) {
                                    StatusPill(text: "Retention review", color: .orange, symbol: "clock.badge.exclamationmark")
                                }
                            }
                            Text(item.outputDirectory.path).font(.callout.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                            Text("\(item.document.findings.count) findings · \(item.document.coverage.count) coverage records · \(item.document.tools.count) instruments")
                                .font(.callout)
                            HStack {
                                Button("Open Scan") { coordinator.loadHistoryItem(item) }
                                Menu {
                                    Button("Validated JSON…") { coordinator.exportValidatedJSON(item) }
                                    Button("Offline HTML…") { coordinator.exportOfflineHTML(item) }
                                    Divider()
                                    Button("Portable Evidence Directory…") { coordinator.exportEvidenceBundle(item) }
                                } label: {
                                    Label("Export", systemImage: "square.and.arrow.up")
                                }
                                .disabled(coordinator.exportState.isWorking)
                                .accessibilityIdentifier("history.export.\(item.id)")
                                Button("Move to Trash…", role: .destructive) { coordinator.moveHistoryItemToTrash(item) }
                                    .disabled(coordinator.phase.isActive)
                                    .accessibilityIdentifier("history.trash.\(item.id)")
                                Text(item.document.completedAt).font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                        }
                        .macScopeCard()
                    }
                    ForEach(coordinator.historyWarnings, id: \.self) { warning in
                        Label(warning, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .macScopeCard()
                    }
                }
            }
            .frame(maxWidth: MacScopeStyle.maximumReadableWidth, alignment: .leading)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle("History")
    }

    @ViewBuilder
    private var exportStatus: some View {
        switch coordinator.exportState {
        case .idle:
            EmptyView()
        case let .working(message):
            HStack(spacing: 12) {
                ProgressView()
                    .controlSize(.small)
                Text(message).font(.callout.weight(.medium))
            }
            .macScopeCard()
        case let .completed(message):
            Label(message, systemImage: "checkmark.circle.fill")
                .font(.callout)
                .foregroundStyle(.green)
                .textSelection(.enabled)
                .macScopeCard()
        case let .failed(message):
            Label(message, systemImage: "xmark.octagon.fill")
                .font(.callout)
                .foregroundStyle(.red)
                .textSelection(.enabled)
                .macScopeCard()
        }
    }
}

struct FindingsLibraryView: View {
    @ObservedObject var coordinator: ScanCoordinator
    @State private var search = ""

    private var visibleRules: [FindingsCatalogEntry] {
        let rules = coordinator.findingsCatalog?.rules ?? []
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return rules }
        return rules.filter {
            $0.title.localizedCaseInsensitiveContains(query)
                || $0.explanation.localizedCaseInsensitiveContains(query)
                || $0.toolID.localizedCaseInsensitiveContains(query)
                || $0.id.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: MacScopeStyle.contentSpacing) {
                SectionHeading(
                    eyebrow: "Master findings documentation",
                    title: "How MacScope interprets evidence",
                    subtitle: "This reader is generated from the same structured catalog the Go engine uses to validate every emitted finding source."
                )
                TextField("Search rules, instruments, and explanations", text: $search)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("catalog.search")
                if let error = coordinator.findingsCatalogError {
                    Label(error, systemImage: "xmark.octagon.fill")
                        .foregroundStyle(.red)
                        .macScopeCard()
                } else {
                    ForEach(visibleRules) { rule in
                        DisclosureGroup {
                            VStack(alignment: .leading, spacing: 14) {
                                catalogSection("What it means", values: [rule.explanation])
                                catalogSection("Detection logic", values: [rule.detectionLogic])
                                catalogSection("Expected state", values: [rule.expectedState])
                                catalogSection("Observed-state interpretation", values: [rule.observedStateInterpretation])
                                catalogSection("Severity rationale", values: [rule.severityRationale])
                                catalogSection("Expected evidence", values: rule.expectedEvidence)
                                catalogSection("Possible false positives", values: rule.possibleFalsePositives)
                                catalogSection("Interpretation limits", values: rule.limitations)
                                catalogSection("Remediation", values: rule.remediation)
                                catalogSection("Post-remediation verification", values: rule.verification)
                                catalogSection("Supported macOS", values: rule.supportedMacOS)
                                VStack(alignment: .leading, spacing: 5) {
                                    Text("Authoritative references").font(.subheadline.weight(.semibold))
                                    ForEach(rule.references, id: \.self) { reference in
                                        Button(reference) { coordinator.openReference(reference) }
                                            .buttonStyle(.link)
                                    }
                                }
                            }
                            .padding(.top, 12)
                        } label: {
                            HStack {
                                Image(systemName: catalogSymbol(rule.category))
                                    .foregroundStyle(.red)
                                    .frame(width: 26)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(rule.title).font(.headline)
                                    Text("\(rule.toolID) · \(rule.id) · \(displayName(rule.category))")
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                StatusPill(text: rule.ruleMatch == "exact" ? rule.ruleValue : "Rule family", color: .blue, symbol: "doc.text.magnifyingglass")
                            }
                        }
                        .macScopeCard()
                    }
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

    private func catalogSection(_ title: String, values: [String]) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.subheadline.weight(.semibold))
            ForEach(Array(values.enumerated()), id: \.offset) { _, value in
                Text(value).foregroundStyle(.secondary).textSelection(.enabled)
            }
        }
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
                    Divider()
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: "clock.arrow.circlepath").foregroundStyle(.red).frame(width: 22)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Evidence retention").font(.headline)
                            Text("A policy only flags older scans. MacScope never deletes evidence automatically; every removal requires confirmation and moves the scan to Trash.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Picker("Evidence retention", selection: Binding(
                            get: { coordinator.retentionPolicy },
                            set: { coordinator.setRetentionPolicy($0) }
                        )) {
                            ForEach(HistoryRetentionPolicy.allCases) { policy in
                                Text(policy.title).tag(policy)
                            }
                        }
                        .labelsHidden()
                        .frame(width: 180)
                        .accessibilityIdentifier("settings.retention")
                    }
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

private func severityCount(_ document: ScanDocument, _ severity: String) -> Int {
    document.findings.filter { $0.severity == severity }.count
}

private func knownExploitedCount(_ document: ScanDocument) -> Int {
    document.findings.filter { finding in finding.vulnerabilities.contains(where: \.knownExploited) }.count
}

private func gapCount(_ document: ScanDocument) -> Int {
    document.coverage.filter { $0.status != "complete" }.count
}

private func findingCategories(_ document: ScanDocument?) -> [String] {
    Array(Set((document?.findings ?? []).map(\.category))).sorted()
}

private func findingInstruments(_ document: ScanDocument?) -> [String] {
    Array(Set((document?.findings ?? []).flatMap { $0.sources.map(\.toolID) })).sorted()
}

private struct ScanComparison {
    let newCount: Int
    let persistentCount: Int
    let resolvedCount: Int
    let coverageComparable: Bool
}

private func compareLatestScans(_ history: [ScanHistoryItem]) -> ScanComparison? {
    guard history.count >= 2 else { return nil }
    let current = history[0].document
    let previous = history[1].document
    let currentFindings = Set(current.findings.map(\.id))
    let previousFindings = Set(previous.findings.map(\.id))
    let currentCoverage = Dictionary(uniqueKeysWithValues: current.coverage.map { ($0.id, $0.status) })
    let previousCoverage = Dictionary(uniqueKeysWithValues: previous.coverage.map { ($0.id, $0.status) })
    let currentTools = Dictionary(uniqueKeysWithValues: current.tools.map { ($0.id, $0.version) })
    let previousTools = Dictionary(uniqueKeysWithValues: previous.tools.map { ($0.id, $0.version) })
    let coverageComparable = currentCoverage == previousCoverage && currentTools == previousTools
    return ScanComparison(
        newCount: currentFindings.subtracting(previousFindings).count,
        persistentCount: currentFindings.intersection(previousFindings).count,
        resolvedCount: previousFindings.subtracting(currentFindings).count,
        coverageComparable: coverageComparable
    )
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

private func coveragePresentationStatus(_ record: CoverageRecord) -> String {
    let reason = (record.reason ?? "").lowercased()
    if reason.contains("permission") || reason.contains("not permitted") || reason.contains("operation not permitted") {
        return "Permission denied"
    }
    if reason.contains("exclude") {
        return "Excluded"
    }
    if reason.contains("icloud") || reason.contains("dataless") || reason.contains("cloud-only") {
        return "Cloud-only skipped"
    }
    if reason.contains("network") || reason.contains("http") || reason.contains("download") {
        return "Network unavailable"
    }
    if reason.contains("unavailable") || reason.contains("not found") || reason.contains("executable") {
        return "Tool unavailable"
    }
    return displayName(record.status)
}

private func preflightColor(_ state: PreflightState) -> Color {
    switch state {
    case .passed: .green
    case .warning, .running: .orange
    case .failed: .red
    case .pending: .secondary
    }
}

private func catalogSymbol(_ category: String) -> String {
    switch category {
    case "os_vulnerability": "apple.logo"
    case "software_vulnerability": "shippingbox"
    case "configuration": "switch.2"
    case "network_exposure": "network"
    case "persistence": "arrow.triangle.2.circlepath"
    case "coverage_gap": "scope"
    case "tool_error": "wrench.and.screwdriver"
    default: "doc.text.magnifyingglass"
    }
}

private func preflightSymbol(_ state: PreflightState) -> String {
    switch state {
    case .passed: "checkmark.circle.fill"
    case .warning: "exclamationmark.triangle.fill"
    case .failed: "xmark.octagon.fill"
    case .running: "arrow.triangle.2.circlepath"
    case .pending: "circle.dashed"
    }
}

private func copyActivity(_ entries: [ActivityEntry]) {
    let pasteboard = NSPasteboard.general
    pasteboard.clearContents()
    pasteboard.setString(renderActivity(entries), forType: .string)
}

private func saveRawActivity(_ entries: [ActivityEntry]) {
    saveActivityText(renderActivity(entries), suggestedName: "MacScope-activity-raw.log")
}

private func saveRedactedActivity(_ entries: [ActivityEntry]) {
    saveActivityText(redactActivity(renderActivity(entries)), suggestedName: "MacScope-activity-redacted.log")
}

private func renderActivity(_ entries: [ActivityEntry]) -> String {
    entries.map { entry in
        "[\(entry.timestamp)] [\(entry.collectorID)] [\(entry.kind)] \(entry.summary)\n\(entry.detail)"
    }.joined(separator: "\n\n") + "\n"
}

private func redactActivity(_ content: String) -> String {
    var redacted = content
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let username = NSUserName()
    let hostname = Host.current().localizedName ?? ""
    for replacement in [(home, "<HOME>"), (username, "<USER>"), (hostname, "<HOST>")] where !replacement.0.isEmpty {
        redacted = redacted.replacingOccurrences(of: replacement.0, with: replacement.1, options: [.caseInsensitive])
    }
    return redacted
}

private func saveActivityText(_ content: String, suggestedName: String) {
    let panel = NSSavePanel()
    panel.title = "Save MacScope activity"
    panel.nameFieldStringValue = suggestedName
    guard panel.runModal() == .OK, let url = panel.url else { return }
    do {
        guard let data = content.data(using: .utf8) else {
            throw ScanProcessError.protocolViolation("encode activity export as UTF-8")
        }
        try data.write(to: url, options: [.atomic, .withoutOverwriting])
    } catch {
        let alert = NSAlert(error: error)
        alert.messageText = "MacScope could not save the activity export"
        alert.runModal()
    }
}
