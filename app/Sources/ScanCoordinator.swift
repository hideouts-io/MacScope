import AppKit
import CryptoKit
import Darwin
import Foundation

enum ScanProcessError: LocalizedError {
    case alreadyRunning
    case missingEngine(String)
    case createEventLog(String)
    case launch(String)
    case protocolViolation(String)
    case readReport(String)

    var errorDescription: String? {
        switch self {
        case .alreadyRunning:
            "A MacScope scan is already running."
        case let .missingEngine(path):
            "The bundled MacScope scan engine is missing or not executable at \(path). Rebuild or reinstall the application."
        case let .createEventLog(path):
            "MacScope could not create the private event log at \(path). Check folder permissions and available disk space."
        case let .launch(message):
            "The MacScope scan engine could not be launched: \(message)"
        case let .protocolViolation(message):
            "The scan engine returned an invalid event stream: \(message)"
        case let .readReport(message):
            "The completed scan report could not be opened: \(message)"
        }
    }
}

enum ScanExportError: LocalizedError {
    case destinationExists(String)
    case engineUnavailable(String)
    case reportFailed(Int32, String)

    var errorDescription: String? {
        switch self {
        case let .destinationExists(path):
            "The export destination already exists at \(path). Choose another folder or remove the existing export explicitly."
        case let .engineUnavailable(path):
            "The bundled MacScope report engine is missing or not executable at \(path). Reinstall MacScope from a verified release."
        case let .reportFailed(status, diagnostic):
            "The MacScope report engine rejected the scan or exited with status \(status): \(diagnostic)"
        }
    }
}

final class ScanProcess {
    private let process: Process
    private let stdoutQueue: DispatchQueue
    private let stderrQueue: DispatchQueue
    private let streamGroup: DispatchGroup

    init() {
        process = Process()
        stdoutQueue = DispatchQueue(label: "io.hideouts.MacScope.scan.stdout", qos: .userInitiated)
        stderrQueue = DispatchQueue(label: "io.hideouts.MacScope.scan.stderr", qos: .utility)
        streamGroup = DispatchGroup()
    }

    func start(
        engineURL: URL,
        runtimeRootURL: URL,
        arguments: [String],
        eventLogURL: URL,
        onEnvelope: @escaping (ScanEventEnvelope) -> Void,
        onStandardError: @escaping (String) -> Void,
        onProtocolError: @escaping (Error) -> Void,
        onTermination: @escaping (Int32) -> Void
    ) throws {
        if process.isRunning {
            throw ScanProcessError.alreadyRunning
        }

        guard FileManager.default.isExecutableFile(atPath: engineURL.path) else {
            throw ScanProcessError.missingEngine(engineURL.path)
        }
        guard FileManager.default.createFile(atPath: eventLogURL.path, contents: nil) else {
            throw ScanProcessError.createEventLog(eventLogURL.path)
        }
        let eventLog = try FileHandle(forWritingTo: eventLogURL)
        let standardOutput = Pipe()
        let standardError = Pipe()

        process.executableURL = engineURL
        process.arguments = arguments
        process.standardOutput = standardOutput
        process.standardError = standardError
        process.standardInput = FileHandle.nullDevice
        var environment = ProcessInfo.processInfo.environment
        environment["MACSCOPE_NO_BANNER"] = "1"
        environment["MACSCOPE_NO_PROGRESS"] = "1"
        environment["MACSCOPE_RUNTIME_ROOT"] = runtimeRootURL.path
        process.environment = environment

        streamGroup.enter()
        stdoutQueue.async { [weak self] in
            defer {
                try? eventLog.close()
                self?.streamGroup.leave()
            }
            do {
                try readEventStream(
                    from: standardOutput.fileHandleForReading,
                    eventLog: eventLog,
                    onEnvelope: onEnvelope
                )
            } catch {
                DispatchQueue.main.async {
                    onProtocolError(error)
                    self?.cancel()
                }
            }
        }

        streamGroup.enter()
        stderrQueue.async { [weak self] in
            defer { self?.streamGroup.leave() }
            do {
                try readTextStream(from: standardError.fileHandleForReading, onText: onStandardError)
            } catch {
                DispatchQueue.main.async {
                    onProtocolError(ScanProcessError.protocolViolation("read scanner stderr: \(error.localizedDescription)"))
                    self?.cancel()
                }
            }
        }

        process.terminationHandler = { [weak self] terminatedProcess in
            guard let self else { return }
            self.streamGroup.notify(queue: .main) {
                onTermination(terminatedProcess.terminationStatus)
            }
        }

        do {
            try process.run()
        } catch {
            try? eventLog.close()
            throw ScanProcessError.launch(error.localizedDescription)
        }
    }

    func cancel() {
        if process.isRunning {
            process.terminate()
        }
    }
}

private func readEventStream(
    from source: FileHandle,
    eventLog: FileHandle,
    onEnvelope: @escaping (ScanEventEnvelope) -> Void
) throws {
    let decoder = JSONDecoder()
    var buffer = Data()
    var previousSequence: UInt64 = 0

    while let chunk = try readPipeChunk(from: source, maximumBytes: 64 * 1024) {
        try eventLog.write(contentsOf: chunk)
        buffer.append(chunk)
        let split = splitCompleteLines(buffer)
        buffer = split.remainder
        for line in split.lines where !line.isEmpty {
            let envelope: ScanEventEnvelope
            do {
                envelope = try decoder.decode(ScanEventEnvelope.self, from: line)
            } catch {
                throw ScanProcessError.protocolViolation("decode NDJSON event: \(error.localizedDescription)")
            }
            guard envelope.schemaVersion == "1" else {
                throw ScanProcessError.protocolViolation("unsupported schema version \(envelope.schemaVersion)")
            }
            guard envelope.sequence == previousSequence + 1 else {
                throw ScanProcessError.protocolViolation("expected sequence \(previousSequence + 1), received \(envelope.sequence)")
            }
            previousSequence = envelope.sequence
            DispatchQueue.main.async {
                onEnvelope(envelope)
            }
        }
    }
    if !buffer.isEmpty {
        throw ScanProcessError.protocolViolation("event stream ended with an incomplete NDJSON line")
    }
}

private func readTextStream(from source: FileHandle, onText: @escaping (String) -> Void) throws {
    while let chunk = try readPipeChunk(from: source, maximumBytes: 16 * 1024) {
        let text = String(decoding: chunk, as: UTF8.self)
        DispatchQueue.main.async {
            onText(text)
        }
    }
}

private func readPipeChunk(from source: FileHandle, maximumBytes: Int) throws -> Data? {
    guard maximumBytes > 0 else {
        throw ScanProcessError.protocolViolation("pipe read size must be greater than zero")
    }
    var buffer = [UInt8](repeating: 0, count: maximumBytes)
    while true {
        let bytesRead = buffer.withUnsafeMutableBytes { rawBuffer in
            Darwin.read(source.fileDescriptor, rawBuffer.baseAddress, maximumBytes)
        }
        if bytesRead > 0 {
            return Data(buffer.prefix(bytesRead))
        }
        if bytesRead == 0 {
            return nil
        }
        let errorCode = errno
        if errorCode == EINTR {
            continue
        }
        guard let posixError = POSIXErrorCode(rawValue: errorCode) else {
            throw ScanProcessError.protocolViolation("read pipe file descriptor \(source.fileDescriptor): unknown POSIX error \(errorCode)")
        }
        throw POSIXError(posixError)
    }
}

private func splitCompleteLines(_ data: Data) -> (lines: [Data], remainder: Data) {
    var lines: [Data] = []
    var startIndex = data.startIndex
    var index = data.startIndex
    while index < data.endIndex {
        if data[index] == 0x0A {
            lines.append(data[startIndex ..< index])
            startIndex = data.index(after: index)
        }
        index = data.index(after: index)
    }
    return (lines, Data(data[startIndex ..< data.endIndex]))
}

@MainActor
final class ScanCoordinator: ObservableObject {
    @Published var selectedSection: AppSection = .dashboard
    @Published private(set) var phase: ScanPhase = .idle
    @Published private(set) var progressPercent = 0
    @Published private(set) var progressMessage = "Ready for an evidence-first scan"
    @Published private(set) var activeCollector = "macscope"
    @Published private(set) var elapsedSeconds: TimeInterval = 0
    @Published private(set) var activities: [ActivityEntry] = []
    @Published private(set) var instruments: [InstrumentActivity] = initialInstruments()
    @Published private(set) var scanDocument: ScanDocument?
    @Published private(set) var outputDirectory: URL?
    @Published private(set) var eventLogURL: URL?
    @Published private(set) var failureMessage: String?
    @Published private(set) var preflightState: PreflightState = .pending
    @Published private(set) var preflightChecks: [PreflightCheck] = []
    @Published private(set) var savedProfiles: [SavedScanProfile] = []
    @Published private(set) var history: [ScanHistoryItem] = []
    @Published private(set) var historyWarnings: [String] = []
    @Published private(set) var findingsCatalog: FindingsCatalogDocument?
    @Published private(set) var findingsCatalogError: String?
    @Published private(set) var exportState: ScanExportState = .idle
    @Published private(set) var retentionPolicy: HistoryRetentionPolicy = .keepForever
    @Published var excludedPaths: [String] = discoverOneDrivePaths()
    @Published var findingSearch = ""
    @Published var findingSeverity = "all"
    @Published var findingCategory = "all"
    @Published var findingInstrument = "all"
    @Published var findingConfidence = "all"
    @Published var findingKnownExploitedOnly = false
    @Published var findingRequiresAdminOnly = false
    @Published var findingRequiresRestartOnly = false

    private var scanProcess: ScanProcess?
    private var reportPath: String?
    private var scanStart: Date?
    private var elapsedTimer: Timer?

    init() {
        reloadProfiles()
        reloadHistory()
        loadPreferences()
        loadFindingsCatalog()
    }

    var filteredFindings: [FindingRecord] {
        let findings = scanDocument?.findings ?? []
        return findings.filter { finding in
            let matchesSeverity = findingSeverity == "all" || finding.severity == findingSeverity
            let matchesCategory = findingCategory == "all" || finding.category == findingCategory
            let matchesInstrument = findingInstrument == "all" || finding.sources.contains { $0.toolID == findingInstrument }
            let matchesConfidence = findingConfidence == "all" || finding.confidence == findingConfidence
            let matchesKnownExploited = !findingKnownExploitedOnly || finding.vulnerabilities.contains(where: \.knownExploited)
            let matchesAdmin = !findingRequiresAdminOnly || finding.remediation.requiresAdmin
            let matchesRestart = !findingRequiresRestartOnly || finding.remediation.requiresRestart
            let trimmedSearch = findingSearch.trimmingCharacters(in: .whitespacesAndNewlines)
            let matchesSearch = trimmedSearch.isEmpty
                || finding.title.localizedCaseInsensitiveContains(trimmedSearch)
                || finding.description.localizedCaseInsensitiveContains(trimmedSearch)
                || finding.id.localizedCaseInsensitiveContains(trimmedSearch)
            return matchesSeverity
                && matchesCategory
                && matchesInstrument
                && matchesConfidence
                && matchesKnownExploited
                && matchesAdmin
                && matchesRestart
                && matchesSearch
        }
    }

    func evidence(for finding: FindingRecord) -> [EvidenceRecord] {
        let identifiers = Set(finding.evidenceIDs)
        return (scanDocument?.evidence ?? []).filter { identifiers.contains($0.id) }
    }

    var attentionFindings: [FindingRecord] {
        (scanDocument?.findings ?? []).filter { finding in
            ["critical", "high"].contains(finding.severity)
                || ["configuration", "network_exposure", "persistence", "coverage_gap", "tool_error", "threat_indicator"].contains(finding.category)
                || finding.vulnerabilities.contains(where: \.knownExploited)
        }
    }

    func addExclusion(_ url: URL) {
        let standardizedPath = url.standardizedFileURL.path
        guard standardizedPath != "/", !excludedPaths.contains(standardizedPath) else { return }
        excludedPaths.append(standardizedPath)
        excludedPaths.sort()
    }

    func removeExclusion(_ path: String) {
        excludedPaths.removeAll { $0 == path }
    }

    func runPreflight() {
        guard preflightState != .running else { return }
        preflightState = .running
        preflightChecks = []
        let bundleURL = Bundle.main.bundleURL
        let applicationExecutableURL = Bundle.main.executableURL
        Task {
            let checks = await Task.detached(priority: .userInitiated) {
                performPreflight(bundleURL: bundleURL, applicationExecutableURL: applicationExecutableURL)
            }.value
            preflightChecks = checks
            if checks.contains(where: { $0.state == .failed }) {
                preflightState = .failed
            } else if checks.contains(where: { $0.state == .warning }) {
                preflightState = .warning
            } else {
                preflightState = .passed
            }
        }
    }

    func saveProfile(named name: String) {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else {
            failureMessage = "A scan profile name must not be empty."
            return
        }
        let profile = SavedScanProfile(id: UUID(), name: trimmedName, excludedPaths: excludedPaths.sorted(), createdAt: Date())
        savedProfiles.removeAll { $0.name.localizedCaseInsensitiveCompare(trimmedName) == .orderedSame }
        savedProfiles.append(profile)
        savedProfiles.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        persistProfiles()
    }

    func applyProfile(_ profile: SavedScanProfile) {
        excludedPaths = profile.excludedPaths
    }

    func deleteProfile(_ profile: SavedScanProfile) {
        savedProfiles.removeAll { $0.id == profile.id }
        persistProfiles()
    }

    func loadHistoryItem(_ item: ScanHistoryItem) {
        scanDocument = item.document
        outputDirectory = item.outputDirectory
        eventLogURL = item.outputDirectory.appending(path: "events.ndjson")
        phase = .completed
        selectedSection = .dashboard
    }

    func setRetentionPolicy(_ policy: HistoryRetentionPolicy) {
        retentionPolicy = policy
        persistPreferences()
    }

    func isPastRetention(_ item: ScanHistoryItem) -> Bool {
        guard let days = retentionPolicy.ageInDays,
              let completed = ISO8601DateFormatter().date(from: item.document.completedAt),
              let cutoff = Calendar.current.date(byAdding: .day, value: -days, to: Date())
        else { return false }
        return completed < cutoff
    }

    func moveHistoryItemToTrash(_ item: ScanHistoryItem) {
        guard !phase.isActive else { return }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Move this MacScope scan to Trash?"
        alert.informativeText = "Run \(item.document.runID) and its scan.json, command log, artifacts, and reports will leave MacScope history. You can recover the directory from Trash until Trash is emptied."
        alert.addButton(withTitle: "Move to Trash")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        do {
            var resultingURL: NSURL?
            try FileManager.default.trashItem(at: item.outputDirectory, resultingItemURL: &resultingURL)
            reloadHistory()
        } catch {
            historyWarnings.append("Move \(item.document.runID) to Trash: \(error.localizedDescription)")
        }
    }

    func startStandardScan() {
        guard !phase.isActive else { return }
        if preflightState == .pending {
            selectedSection = .newScan
            runPreflight()
            return
        }
        if preflightState == .running || preflightState == .failed {
            selectedSection = .newScan
            return
        }
        do {
            let locations = try createScanLocations()
            let engineURL = try resolveBundledEngineURL(
                bundleURL: Bundle.main.bundleURL,
                applicationExecutableURL: Bundle.main.executableURL
            )
            let runtimeRootURL = bundledRuntimeRootURL(bundleURL: Bundle.main.bundleURL)

            resetForNewScan(outputDirectory: locations.outputDirectory, eventLogURL: locations.eventLog)
            let arguments = makeScanArguments(
                outputDirectory: locations.outputDirectory,
                dataDirectory: locations.dataDirectory,
                excludedPaths: excludedPaths
            )
            let connector = ScanProcess()
            scanProcess = connector
            phase = .preparing
            selectedSection = .liveActivity
            beginElapsedTimer()

            try connector.start(
                engineURL: engineURL,
                runtimeRootURL: runtimeRootURL,
                arguments: arguments,
                eventLogURL: locations.eventLog,
                onEnvelope: { [weak self] envelope in self?.handle(envelope) },
                onStandardError: { [weak self] text in self?.handleStandardError(text) },
                onProtocolError: { [weak self] error in self?.handleProtocolError(error) },
                onTermination: { [weak self] status in self?.handleTermination(status) }
            )
        } catch {
            finishWithFailure(error.localizedDescription)
        }
    }

    func cancelScan() {
        guard phase.isActive else { return }
        phase = .canceling
        progressMessage = "Canceling the active collector and preserving completed evidence"
        scanProcess?.cancel()
    }

    func revealOutput() {
        guard let outputDirectory else { return }
        NSWorkspace.shared.activateFileViewerSelecting([outputDirectory])
    }

    func exportValidatedJSON(_ item: ScanHistoryItem) {
        guard !exportState.isWorking else { return }
        let engineURL: URL
        do {
            engineURL = try resolveBundledEngineURL(
                bundleURL: Bundle.main.bundleURL,
                applicationExecutableURL: Bundle.main.executableURL
            )
        } catch {
            exportState = .failed("Locate bundled report engine: \(error.localizedDescription)")
            return
        }
        let panel = NSSavePanel()
        panel.title = "Export validated MacScope JSON"
        panel.nameFieldStringValue = "MacScope-\(item.document.runID).json"
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        exportState = .working("Validating scan evidence before exporting JSON")
        Task {
            do {
                try await Task.detached(priority: .userInitiated) {
                    try validateScanForExport(engineURL: engineURL, reportURL: item.reportURL)
                    let data = try Data(contentsOf: item.reportURL, options: .mappedIfSafe)
                    try data.write(to: destination, options: .atomic)
                }.value
                exportState = .completed("Validated JSON exported to \(destination.path)")
            } catch {
                exportState = .failed("Export validated JSON: \(error.localizedDescription)")
            }
        }
    }

    func exportOfflineHTML(_ item: ScanHistoryItem) {
        guard !exportState.isWorking else { return }
        let engineURL: URL
        do {
            engineURL = try resolveBundledEngineURL(
                bundleURL: Bundle.main.bundleURL,
                applicationExecutableURL: Bundle.main.executableURL
            )
        } catch {
            exportState = .failed("Locate bundled report engine: \(error.localizedDescription)")
            return
        }
        let panel = NSSavePanel()
        panel.title = "Export offline MacScope report"
        panel.nameFieldStringValue = "MacScope-\(item.document.runID).html"
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        exportState = .working("Validating scan evidence and generating offline HTML")
        Task {
            do {
                try await Task.detached(priority: .userInitiated) {
                    try withTemporaryDirectory { directory in
                        let generated = directory.appending(path: "report.html")
                        try runReportEngine(engineURL: engineURL, reportURL: item.reportURL, outputURL: generated)
                        let data = try Data(contentsOf: generated, options: .mappedIfSafe)
                        try data.write(to: destination, options: .atomic)
                    }
                }.value
                exportState = .completed("Offline HTML exported to \(destination.path)")
            } catch {
                exportState = .failed("Export offline HTML: \(error.localizedDescription)")
            }
        }
    }

    func exportEvidenceBundle(_ item: ScanHistoryItem) {
        guard !exportState.isWorking else { return }
        let engineURL: URL
        do {
            engineURL = try resolveBundledEngineURL(
                bundleURL: Bundle.main.bundleURL,
                applicationExecutableURL: Bundle.main.executableURL
            )
        } catch {
            exportState = .failed("Locate bundled report engine: \(error.localizedDescription)")
            return
        }
        let panel = NSOpenPanel()
        panel.title = "Choose a folder for the portable evidence export"
        panel.prompt = "Export Evidence"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let parent = panel.url else { return }
        let destination = parent.appending(path: "MacScope-\(item.document.runID)-evidence", directoryHint: .isDirectory)
        exportState = .working("Validating and copying the complete evidence directory")
        Task {
            do {
                try await Task.detached(priority: .userInitiated) {
                    guard !FileManager.default.fileExists(atPath: destination.path) else {
                        throw ScanExportError.destinationExists(destination.path)
                    }
                    try validateScanForExport(engineURL: engineURL, reportURL: item.reportURL)
                    try FileManager.default.copyItem(at: item.outputDirectory, to: destination)
                }.value
                exportState = .completed("Portable evidence exported to \(destination.path)")
            } catch {
                exportState = .failed("Export portable evidence: \(error.localizedDescription)")
            }
        }
    }

    func openReference(_ value: String) {
        guard let url = URL(string: value), ["https", "http"].contains(url.scheme?.lowercased()) else { return }
        NSWorkspace.shared.open(url)
    }

    private func handle(_ envelope: ScanEventEnvelope) {
        switch envelope.type {
        case .scanStarted:
            phase = .running
            appendActivity(envelope, collectorID: "macscope", kind: "Scan", summary: "Scan started", detail: envelope.scanStarted?.outputDirectory ?? "", isPrivate: false, isError: false)
        case .progress:
            guard let event = envelope.progress else { return }
            progressPercent = event.percent
            progressMessage = event.message
            activeCollector = event.collectorID
            markInstrument(event.collectorID, state: .running, detail: event.message)
            appendActivity(envelope, collectorID: event.collectorID, kind: "Progress", summary: event.message, detail: "\(event.percent)% complete", isPrivate: false, isError: false)
        case .commandStarted:
            guard let event = envelope.commandStarted else { return }
            let command = ([event.executable] + event.arguments).map(shellQuoted).joined(separator: " ")
            markInstrument(event.collectorID, state: .running, detail: event.commandID)
            appendActivity(envelope, collectorID: event.collectorID, kind: "Command", summary: event.commandID, detail: command, isPrivate: event.mayContainPrivateData, isError: false)
        case .commandOutput:
            guard let event = envelope.commandOutput else { return }
            let text = renderOutput(event.data)
            appendActivity(envelope, collectorID: event.collectorID, kind: event.stream.uppercased(), summary: event.commandID, detail: text, isPrivate: event.mayContainPrivateData, isError: event.stream == "stderr")
        case .commandCompleted:
            guard let event = envelope.commandCompleted else { return }
            let failed = event.exitCode != 0 || !(event.executionError ?? "").isEmpty
            let detail = failed ? (event.executionError ?? "Exit code \(event.exitCode)") : "Exited successfully"
            markInstrument(event.collectorID, state: failed ? .failed : .completed, detail: detail)
            appendActivity(envelope, collectorID: event.collectorID, kind: "Result", summary: event.commandID, detail: detail, isPrivate: false, isError: failed)
        case .scanCompleted:
            reportPath = envelope.scanCompleted?.reportPath
            progressPercent = 100
            progressMessage = "Scan evidence validated and written"
            appendActivity(envelope, collectorID: "macscope", kind: "Scan", summary: "Scan completed", detail: reportPath ?? "", isPrivate: false, isError: false)
        case .scanFailed:
            let message = envelope.scanFailed?.message ?? "The scan failed without a message."
            failureMessage = message
            let canceled = envelope.scanFailed?.errorType == "canceled"
            for index in instruments.indices {
                if instruments[index].state == .running {
                    instruments[index].state = canceled ? .canceled : .failed
                    instruments[index].detail = message
                } else if instruments[index].state == .queued {
                    instruments[index].state = .notScanned
                    instruments[index].detail = canceled ? "Scan canceled before this instrument ran" : "Earlier failure prevented this instrument from running"
                }
            }
            appendActivity(envelope, collectorID: "macscope", kind: "Error", summary: "Scan failed", detail: message, isPrivate: false, isError: true)
        }
    }

    private func handleStandardError(_ text: String) {
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        let syntheticSequence = (activities.last?.id ?? 0) + 1_000_000
        activities.append(ActivityEntry(id: syntheticSequence, timestamp: isoTimestamp(Date()), collectorID: "macscope", kind: "Engine error", summary: "Scanner diagnostic", detail: text, isPrivate: true, isError: true))
        trimActivityBuffer()
    }

    private func handleProtocolError(_ error: Error) {
        failureMessage = error.localizedDescription
    }

    private func handleTermination(_ status: Int32) {
        scanProcess = nil
        stopElapsedTimer()
        if status == 0, let reportPath {
            do {
                scanDocument = try decodeScanDocument(at: URL(fileURLWithPath: reportPath))
                phase = .completed
                reloadHistory()
                selectedSection = .dashboard
                return
            } catch {
                finishWithFailure(error.localizedDescription)
                return
            }
        }
        let message = failureMessage ?? "The scan engine exited with status \(status). Open Live Activity for the preserved diagnostic output."
        finishWithFailure(message)
    }

    private func finishWithFailure(_ message: String) {
        stopElapsedTimer()
        phase = .failed(message)
        failureMessage = message
    }

    private func resetForNewScan(outputDirectory: URL, eventLogURL: URL) {
        self.outputDirectory = outputDirectory
        self.eventLogURL = eventLogURL
        scanDocument = nil
        reportPath = nil
        failureMessage = nil
        progressPercent = 0
        progressMessage = "Launching the local scan engine"
        activeCollector = "macscope"
        activities = []
        instruments = initialInstruments()
        elapsedSeconds = 0
        scanStart = Date()
    }

    private func appendActivity(
        _ envelope: ScanEventEnvelope,
        collectorID: String,
        kind: String,
        summary: String,
        detail: String,
        isPrivate: Bool,
        isError: Bool
    ) {
        activities.append(ActivityEntry(id: envelope.sequence, timestamp: envelope.timestamp, collectorID: collectorID, kind: kind, summary: summary, detail: detail, isPrivate: isPrivate, isError: isError))
        trimActivityBuffer()
    }

    private func trimActivityBuffer() {
        let maximumVisibleEvents = 1_000
        if activities.count > maximumVisibleEvents {
            activities.removeFirst(activities.count - maximumVisibleEvents)
        }
    }

    private func markInstrument(_ collectorID: String, state: InstrumentActivity.State, detail: String) {
        guard let index = instruments.firstIndex(where: { $0.id == collectorID }) else { return }
        instruments[index].state = state
        instruments[index].detail = detail
    }

    private func beginElapsedTimer() {
        elapsedTimer?.invalidate()
        elapsedTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.updateElapsedTime()
            }
        }
    }

    private func updateElapsedTime() {
        guard let scanStart else { return }
        elapsedSeconds = Date().timeIntervalSince(scanStart)
    }

    private func stopElapsedTimer() {
        elapsedTimer?.invalidate()
        elapsedTimer = nil
    }

    private func reloadProfiles() {
        do {
            let url = try applicationSupportDirectory().appending(path: "profiles.json")
            guard FileManager.default.fileExists(atPath: url.path) else {
                savedProfiles = []
                return
            }
            let data = try Data(contentsOf: url)
            savedProfiles = try JSONDecoder().decode([SavedScanProfile].self, from: data)
                .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        } catch {
            savedProfiles = []
            failureMessage = "Load saved scan profiles: \(error.localizedDescription)"
        }
    }

    private func persistProfiles() {
        do {
            let directory = try applicationSupportDirectory()
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let data = try JSONEncoder().encode(savedProfiles)
            try data.write(to: directory.appending(path: "profiles.json"), options: .atomic)
        } catch {
            failureMessage = "Save scan profiles: \(error.localizedDescription)"
        }
    }

    private func reloadHistory() {
        do {
            let result = try loadScanHistory()
            history = result.items
            historyWarnings = result.warnings
            do {
                try persistHistoryIndex(result.items)
            } catch {
                historyWarnings.append("Update local history index: \(error.localizedDescription)")
            }
        } catch {
            history = []
            historyWarnings = ["Load scan history: \(error.localizedDescription)"]
        }
    }

    private func loadPreferences() {
        do {
            let url = try applicationSupportDirectory().appending(path: "preferences.json")
            guard FileManager.default.fileExists(atPath: url.path) else { return }
            let preferences = try JSONDecoder().decode(AppPreferences.self, from: Data(contentsOf: url))
            guard preferences.schemaVersion == "1" else {
                throw ScanProcessError.readReport("unsupported preferences schema \(preferences.schemaVersion)")
            }
            retentionPolicy = preferences.historyRetention
        } catch {
            historyWarnings.append("Load application preferences: \(error.localizedDescription)")
        }
    }

    private func persistPreferences() {
        do {
            let directory = try applicationSupportDirectory()
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let preferences = AppPreferences(schemaVersion: "1", historyRetention: retentionPolicy)
            try JSONEncoder().encode(preferences).write(to: directory.appending(path: "preferences.json"), options: .atomic)
        } catch {
            historyWarnings.append("Save application preferences: \(error.localizedDescription)")
        }
    }

    private func loadFindingsCatalog() {
        do {
            guard let url = Bundle.main.url(forResource: "findings-catalog", withExtension: "json") else {
                throw ScanProcessError.readReport("bundled findings-catalog.json is missing")
            }
            let document = try JSONDecoder().decode(FindingsCatalogDocument.self, from: Data(contentsOf: url))
            guard document.schemaVersion == "1", !document.rules.isEmpty else {
                throw ScanProcessError.readReport("findings catalog schema is unsupported or empty")
            }
            findingsCatalog = document
            findingsCatalogError = nil
        } catch {
            findingsCatalog = nil
            findingsCatalogError = error.localizedDescription
        }
    }
}

private func makeScanArguments(outputDirectory: URL, dataDirectory: URL, excludedPaths: [String]) -> [String] {
    var arguments = [
        "scan",
        "--output", outputDirectory.path,
        "--data-directory", dataDirectory.path,
        "--events-json"
    ]
    for path in excludedPaths.sorted() {
        arguments.append(contentsOf: ["--exclude", path])
    }
    return arguments
}

private func createScanLocations() throws -> (outputDirectory: URL, eventLog: URL, dataDirectory: URL) {
    let fileManager = FileManager.default
    let support = try fileManager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    let applicationDirectory = support.appending(path: "MacScope", directoryHint: .isDirectory)
    let scansDirectory = applicationDirectory.appending(path: "Scans", directoryHint: .isDirectory)
    let dataDirectory = applicationDirectory.appending(path: "Data", directoryHint: .isDirectory)
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.dateFormat = "yyyyMMdd-HHmmss"
    let output = scansDirectory.appending(path: formatter.string(from: Date()), directoryHint: .isDirectory)
    try fileManager.createDirectory(at: output, withIntermediateDirectories: true)
    try fileManager.createDirectory(at: dataDirectory, withIntermediateDirectories: true)
    return (output, output.appending(path: "events.ndjson"), dataDirectory)
}

private func decodeScanDocument(at url: URL) throws -> ScanDocument {
    do {
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        let document = try JSONDecoder().decode(ScanDocument.self, from: data)
        guard document.schemaVersion == "1" else {
            throw ScanProcessError.readReport("unsupported scan schema version \(document.schemaVersion) at \(url.path)")
        }
        return document
    } catch let error as ScanProcessError {
        throw error
    } catch {
        throw ScanProcessError.readReport("\(url.path): \(error.localizedDescription)")
    }
}

private func validateScanForExport(engineURL: URL, reportURL: URL) throws {
    try withTemporaryDirectory { directory in
        try runReportEngine(engineURL: engineURL, reportURL: reportURL, outputURL: directory.appending(path: "validation.html"))
    }
}

private func runReportEngine(engineURL: URL, reportURL: URL, outputURL: URL) throws {
    guard FileManager.default.isExecutableFile(atPath: engineURL.path) else {
        throw ScanExportError.engineUnavailable(engineURL.path)
    }
    let process = Process()
    let diagnostics = Pipe()
    process.executableURL = engineURL
    process.arguments = ["report", "--input", reportURL.path, "--output", outputURL.path]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = diagnostics
    try process.run()
    process.waitUntilExit()
    let diagnosticData = diagnostics.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationStatus == 0 else {
        let message = String(decoding: diagnosticData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        throw ScanExportError.reportFailed(process.terminationStatus, message.isEmpty ? "no diagnostic output" : message)
    }
    guard FileManager.default.fileExists(atPath: outputURL.path) else {
        throw ScanExportError.reportFailed(process.terminationStatus, "report engine returned success without creating \(outputURL.path)")
    }
}

private func withTemporaryDirectory(_ operation: (URL) throws -> Void) throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "MacScope-export-\(UUID().uuidString)", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    do {
        try operation(directory)
    } catch {
        let operationError = error
        do {
            try FileManager.default.removeItem(at: directory)
        } catch {
            throw ScanExportError.reportFailed(-1, "export failed with \(operationError.localizedDescription); temporary cleanup also failed at \(directory.path): \(error.localizedDescription)")
        }
        throw operationError
    }
    try FileManager.default.removeItem(at: directory)
}

private func discoverOneDrivePaths() -> [String] {
    let fileManager = FileManager.default
    let home = fileManager.homeDirectoryForCurrentUser
    let candidates = [home, home.appending(path: "Library/CloudStorage", directoryHint: .isDirectory)]
    var paths: [String] = []
    for directory in candidates {
        guard let children = try? fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.isDirectoryKey]) else { continue }
        for child in children where child.lastPathComponent.localizedCaseInsensitiveContains("onedrive") {
            paths.append(child.standardizedFileURL.path)
        }
    }
    return Array(Set(paths)).sorted()
}

private func initialInstruments() -> [InstrumentActivity] {
    [
        InstrumentActivity(id: "macscope", name: "Native MacScope", state: .queued, detail: "macOS controls and host identity"),
        InstrumentActivity(id: "sofa", name: "SOFA", state: .queued, detail: "Apple security releases and CVEs"),
        InstrumentActivity(id: "osquery", name: "osquery + mSCP", state: .queued, detail: "Persistence, exposure, and compliance"),
        InstrumentActivity(id: "syft", name: "Syft", state: .queued, detail: "Software bill of materials"),
        InstrumentActivity(id: "grype", name: "Grype", state: .queued, detail: "Package vulnerability matching")
    ]
}

private func shellQuoted(_ argument: String) -> String {
    if argument.allSatisfy({ $0.isLetter || $0.isNumber || "-._/:=".contains($0) }) {
        return argument
    }
    return "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

private func renderOutput(_ data: Data) -> String {
    if let text = String(data: data, encoding: .utf8) {
        return text
    }
    return "<\(data.count) bytes of non-UTF-8 output; exact bytes remain in events.ndjson>"
}

private func isoTimestamp(_ date: Date) -> String {
    ISO8601DateFormatter().string(from: date)
}

private struct ToolLockDocument: Decodable {
    let schemaVersion: String
    let tools: LockedTools

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case tools
    }
}

private struct LockedTools: Decodable {
    let osquery: LockedTool
    let syft: LockedTool
    let grype: LockedTool
}

private struct LockedTool: Decodable {
    let version: String
    let executableSHA256: String

    enum CodingKeys: String, CodingKey {
        case version
        case executableSHA256 = "executable_sha256"
    }
}

private func performPreflight(bundleURL: URL, applicationExecutableURL: URL?) -> [PreflightCheck] {
    let runtimeRoot = bundledRuntimeRootURL(bundleURL: bundleURL)
    var checks: [PreflightCheck] = []
    do {
        let engine = try resolveBundledEngineURL(bundleURL: bundleURL, applicationExecutableURL: applicationExecutableURL)
        checks.append(PreflightCheck(id: "engine", title: "MacScope scan engine", detail: engine.path, state: .passed, guidance: nil))
    } catch {
        checks.append(PreflightCheck(id: "engine", title: "MacScope scan engine", detail: error.localizedDescription, state: .failed, guidance: "Reinstall MacScope from a verified release."))
    }

    checks.append(contentsOf: verifyBundledTools(runtimeRoot: runtimeRoot))
    checks.append(dataDirectoryPreflight())
    checks.append(diskSpacePreflight())
    checks.append(fullDiskAccessPreflight())
    checks.append(grypeDatabasePreflight())
    checks.append(PreflightCheck(id: "network", title: "Network requirements", detail: "SOFA security data and Grype database updates use HTTPS during the scan.", state: .warning, guidance: "Offline scans remain explicit about unavailable network coverage."))
    return checks
}

private func bundledRuntimeRootURL(bundleURL: URL) -> URL {
    bundleURL
        .appending(path: "Contents", directoryHint: .isDirectory)
        .appending(path: "Resources", directoryHint: .isDirectory)
        .appending(path: "MacScopeRuntime", directoryHint: .isDirectory)
}

private func resolveBundledEngineURL(bundleURL: URL, applicationExecutableURL: URL?) throws -> URL {
    let engine = bundleURL
        .appending(path: "Contents", directoryHint: .isDirectory)
        .appending(path: "Helpers", directoryHint: .isDirectory)
        .appending(path: "macscope", directoryHint: .notDirectory)
        .standardizedFileURL
        .resolvingSymlinksInPath()
    if let applicationExecutableURL {
        let applicationExecutable = applicationExecutableURL.standardizedFileURL.resolvingSymlinksInPath()
        guard engine != applicationExecutable else {
            throw ScanProcessError.missingEngine("\(engine.path) resolved to the SwiftUI application executable")
        }
    }
    let values: URLResourceValues
    do {
        values = try engine.resourceValues(forKeys: [.isRegularFileKey])
    } catch {
        throw ScanProcessError.missingEngine("\(engine.path): \(error.localizedDescription)")
    }
    guard values.isRegularFile == true, FileManager.default.isExecutableFile(atPath: engine.path) else {
        throw ScanProcessError.missingEngine(engine.path)
    }
    return engine
}

private func verifyBundledTools(runtimeRoot: URL) -> [PreflightCheck] {
    let manifestURL = runtimeRoot.appending(path: "tools.lock.json")
    let manifest: ToolLockDocument
    do {
        let data = try Data(contentsOf: manifestURL)
        manifest = try JSONDecoder().decode(ToolLockDocument.self, from: data)
        guard manifest.schemaVersion == "1" else {
            throw ScanProcessError.protocolViolation("unsupported tools manifest schema \(manifest.schemaVersion)")
        }
    } catch {
        return [PreflightCheck(id: "tool-manifest", title: "Bundled tool manifest", detail: error.localizedDescription, state: .failed, guidance: "Reinstall MacScope from a verified release.")]
    }

    let specifications: [(String, String, LockedTool, URL)] = [
        ("osquery", "osquery", manifest.tools.osquery, runtimeRoot.appending(path: ".tools/osquery/\(manifest.tools.osquery.version)/osqueryi")),
        ("syft", "Syft", manifest.tools.syft, runtimeRoot.appending(path: ".tools/syft/\(manifest.tools.syft.version)/syft")),
        ("grype", "Grype", manifest.tools.grype, runtimeRoot.appending(path: ".tools/grype/\(manifest.tools.grype.version)/grype"))
    ]
    return specifications.map { identifier, name, tool, url in
        guard FileManager.default.isExecutableFile(atPath: url.path) else {
            return PreflightCheck(id: identifier, title: "\(name) \(tool.version)", detail: "Bundled executable is missing or not executable.", state: .failed, guidance: "Reinstall MacScope from a verified release.")
        }
        do {
            let digest = try sha256File(url)
            guard digest == tool.executableSHA256 else {
                return PreflightCheck(id: identifier, title: "\(name) \(tool.version)", detail: "SHA-256 mismatch: expected \(tool.executableSHA256), calculated \(digest)", state: .failed, guidance: "Do not scan with this bundle. Reinstall from a verified release.")
            }
            return PreflightCheck(id: identifier, title: "\(name) \(tool.version)", detail: "Executable identity verified: \(digest)", state: .passed, guidance: nil)
        } catch {
            return PreflightCheck(id: identifier, title: "\(name) \(tool.version)", detail: error.localizedDescription, state: .failed, guidance: "Check application integrity and file permissions.")
        }
    }
}

private func dataDirectoryPreflight() -> PreflightCheck {
    do {
        let dataDirectory = try applicationSupportDirectory().appending(path: "Data", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true)
        guard FileManager.default.isWritableFile(atPath: dataDirectory.path) else {
            return PreflightCheck(id: "data-directory", title: "Writable runtime data", detail: dataDirectory.path, state: .failed, guidance: "Restore write access to the MacScope Application Support folder.")
        }
        return PreflightCheck(id: "data-directory", title: "Writable runtime data", detail: dataDirectory.path, state: .passed, guidance: nil)
    } catch {
        return PreflightCheck(id: "data-directory", title: "Writable runtime data", detail: error.localizedDescription, state: .failed, guidance: "Check disk availability and Application Support permissions.")
    }
}

private func diskSpacePreflight() -> PreflightCheck {
    do {
        let directory = try applicationSupportDirectory()
        let values = try directory.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        guard let bytes = values.volumeAvailableCapacityForImportantUsage else {
            return PreflightCheck(id: "disk-space", title: "Available disk space", detail: "macOS did not report available capacity.", state: .warning, guidance: "Keep at least 2 GB free for databases, SBOMs, and evidence artifacts.")
        }
        let formatted = ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
        let minimum: Int64 = 2 * 1024 * 1024 * 1024
        return PreflightCheck(
            id: "disk-space",
            title: "Available disk space",
            detail: "\(formatted) available on the evidence volume.",
            state: bytes >= minimum ? .passed : .failed,
            guidance: bytes >= minimum ? nil : "Free at least 2 GB before scanning."
        )
    } catch {
        return PreflightCheck(id: "disk-space", title: "Available disk space", detail: error.localizedDescription, state: .warning, guidance: "Confirm at least 2 GB is available before scanning.")
    }
}

private func fullDiskAccessPreflight() -> PreflightCheck {
    let mail = FileManager.default.homeDirectoryForCurrentUser.appending(path: "Library/Mail", directoryHint: .isDirectory)
    guard FileManager.default.fileExists(atPath: mail.path) else {
        return PreflightCheck(id: "full-disk-access", title: "Full Disk Access", detail: "No protected Mail directory was present for a bounded readability check.", state: .warning, guidance: "MacScope reports permission-denied coverage explicitly during the scan.")
    }
    if FileManager.default.isReadableFile(atPath: mail.path) {
        return PreflightCheck(id: "full-disk-access", title: "Full Disk Access", detail: "Protected user data appears readable.", state: .passed, guidance: nil)
    }
    return PreflightCheck(id: "full-disk-access", title: "Full Disk Access", detail: "Protected user data is not readable by MacScope.", state: .warning, guidance: "You may grant Full Disk Access in System Settings. MacScope will not change this setting automatically.")
}

private func grypeDatabasePreflight() -> PreflightCheck {
    do {
        let databaseDirectory = try applicationSupportDirectory().appending(path: "Data/grype/db", directoryHint: .isDirectory)
        guard FileManager.default.fileExists(atPath: databaseDirectory.path) else {
            return PreflightCheck(id: "grype-db", title: "Grype vulnerability database", detail: "No local database is installed yet.", state: .warning, guidance: "The first scan downloads and validates the database with visible progress.")
        }
        let children = try FileManager.default.contentsOfDirectory(at: databaseDirectory, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles])
        if children.isEmpty {
            return PreflightCheck(id: "grype-db", title: "Grype vulnerability database", detail: "The database directory is empty.", state: .warning, guidance: "The first scan downloads and validates the database with visible progress.")
        }
        return PreflightCheck(id: "grype-db", title: "Grype vulnerability database", detail: "Local database content is present; Grype performs authoritative validation before matching.", state: .passed, guidance: nil)
    } catch {
        return PreflightCheck(id: "grype-db", title: "Grype vulnerability database", detail: error.localizedDescription, state: .warning, guidance: "The scan will attempt a validated database update.")
    }
}

private func sha256File(_ url: URL) throws -> String {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    var hasher = SHA256()
    while let data = try handle.read(upToCount: 1024 * 1024), !data.isEmpty {
        hasher.update(data: data)
    }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
}

private func applicationSupportDirectory() throws -> URL {
    let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    return support.appending(path: "MacScope", directoryHint: .isDirectory)
}

private func loadScanHistory() throws -> (items: [ScanHistoryItem], warnings: [String]) {
    let scansDirectory = try applicationSupportDirectory().appending(path: "Scans", directoryHint: .isDirectory)
    guard FileManager.default.fileExists(atPath: scansDirectory.path) else {
        return ([], [])
    }
    let directories = try FileManager.default.contentsOfDirectory(at: scansDirectory, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles])
    var items: [ScanHistoryItem] = []
    var warnings: [String] = []
    for directory in directories.sorted(by: { $0.lastPathComponent > $1.lastPathComponent }) {
        let reportURL = directory.appending(path: "scan.json")
        guard FileManager.default.fileExists(atPath: reportURL.path) else { continue }
        do {
            let document = try decodeScanDocument(at: reportURL)
            items.append(ScanHistoryItem(id: document.runID, reportURL: reportURL, outputDirectory: directory, document: document))
        } catch {
            warnings.append("\(reportURL.path): \(error.localizedDescription)")
        }
    }
    return (items, warnings)
}

private func persistHistoryIndex(_ items: [ScanHistoryItem]) throws {
    let scans = items.map { item in
        HistoryIndexEntry(
            runID: item.document.runID,
            directoryName: item.outputDirectory.lastPathComponent,
            completedAt: item.document.completedAt,
            status: item.document.status,
            findingCount: item.document.findings.count,
            coverageCount: item.document.coverage.count,
            toolIdentity: Dictionary(uniqueKeysWithValues: item.document.tools.map { ($0.id, $0.version) })
        )
    }
    let index = HistoryIndexDocument(schemaVersion: "1", generatedAt: isoTimestamp(Date()), scans: scans)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let directory = try applicationSupportDirectory()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try encoder.encode(index).write(to: directory.appending(path: "history-index.json"), options: .atomic)
}
