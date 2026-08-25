import AppKit
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

    while let chunk = try source.read(upToCount: 64 * 1024), !chunk.isEmpty {
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
    while let chunk = try source.read(upToCount: 16 * 1024), !chunk.isEmpty {
        let text = String(decoding: chunk, as: UTF8.self)
        DispatchQueue.main.async {
            onText(text)
        }
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
    @Published var excludedPaths: [String] = discoverOneDrivePaths()
    @Published var findingSearch = ""
    @Published var findingSeverity = "all"

    private var scanProcess: ScanProcess?
    private var reportPath: String?
    private var scanStart: Date?
    private var elapsedTimer: Timer?

    var filteredFindings: [FindingRecord] {
        let findings = scanDocument?.findings ?? []
        return findings.filter { finding in
            let matchesSeverity = findingSeverity == "all" || finding.severity == findingSeverity
            let trimmedSearch = findingSearch.trimmingCharacters(in: .whitespacesAndNewlines)
            let matchesSearch = trimmedSearch.isEmpty
                || finding.title.localizedCaseInsensitiveContains(trimmedSearch)
                || finding.description.localizedCaseInsensitiveContains(trimmedSearch)
                || finding.id.localizedCaseInsensitiveContains(trimmedSearch)
            return matchesSeverity && matchesSearch
        }
    }

    var attentionFindings: [FindingRecord] {
        (scanDocument?.findings ?? []).filter { finding in
            ["critical", "high"].contains(finding.severity)
                || ["coverage_gap", "tool_error", "threat_indicator"].contains(finding.category)
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

    func startStandardScan() {
        guard !phase.isActive else { return }
        do {
            let locations = try createScanLocations()
            guard let engineURL = Bundle.main.url(forAuxiliaryExecutable: "macscope") else {
                throw ScanProcessError.missingEngine("MacScope.app/Contents/Helpers/macscope")
            }

            resetForNewScan(outputDirectory: locations.outputDirectory, eventLogURL: locations.eventLog)
            let arguments = makeScanArguments(outputDirectory: locations.outputDirectory, excludedPaths: excludedPaths)
            let connector = ScanProcess()
            scanProcess = connector
            phase = .preparing
            selectedSection = .liveActivity
            beginElapsedTimer()

            try connector.start(
                engineURL: engineURL,
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
}

private func makeScanArguments(outputDirectory: URL, excludedPaths: [String]) -> [String] {
    var arguments = ["scan", "--output", outputDirectory.path, "--events-json"]
    for path in excludedPaths.sorted() {
        arguments.append(contentsOf: ["--exclude", path])
    }
    return arguments
}

private func createScanLocations() throws -> (outputDirectory: URL, eventLog: URL) {
    let fileManager = FileManager.default
    let support = try fileManager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    let scansDirectory = support.appending(path: "MacScope/Scans", directoryHint: .isDirectory)
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.dateFormat = "yyyyMMdd-HHmmss"
    let output = scansDirectory.appending(path: formatter.string(from: Date()), directoryHint: .isDirectory)
    try fileManager.createDirectory(at: output, withIntermediateDirectories: true)
    return (output, output.appending(path: "events.ndjson"))
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
