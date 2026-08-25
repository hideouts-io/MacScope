import Foundation

enum AppSection: String, CaseIterable, Identifiable {
    case dashboard
    case newScan
    case liveActivity
    case attention
    case findings
    case instruments
    case coverage
    case history
    case findingsLibrary
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .dashboard: "Dashboard"
        case .newScan: "New Scan"
        case .liveActivity: "Live Activity"
        case .attention: "Attention"
        case .findings: "Findings"
        case .instruments: "Instruments"
        case .coverage: "Coverage"
        case .history: "History"
        case .findingsLibrary: "Findings Library"
        case .settings: "Settings"
        }
    }

    var symbol: String {
        switch self {
        case .dashboard: "square.grid.2x2"
        case .newScan: "waveform.badge.magnifyingglass"
        case .liveActivity: "waveform.path.ecg"
        case .attention: "exclamationmark.triangle"
        case .findings: "list.bullet.rectangle"
        case .instruments: "wrench.and.screwdriver"
        case .coverage: "scope"
        case .history: "clock.arrow.circlepath"
        case .findingsLibrary: "books.vertical"
        case .settings: "gearshape"
        }
    }
}

enum ScanPhase: Equatable {
    case idle
    case preparing
    case running
    case canceling
    case completed
    case failed(String)

    var label: String {
        switch self {
        case .idle: "Ready"
        case .preparing: "Preparing"
        case .running: "Scanning"
        case .canceling: "Canceling"
        case .completed: "Completed"
        case .failed: "Needs attention"
        }
    }

    var isActive: Bool {
        self == .preparing || self == .running || self == .canceling
    }
}

enum PreflightState: String {
    case pending
    case running
    case passed
    case warning
    case failed
}

enum ScanExportState: Equatable {
    case idle
    case working(String)
    case completed(String)
    case failed(String)

    var isWorking: Bool {
        if case .working = self { return true }
        return false
    }
}

struct PreflightCheck: Identifiable {
    let id: String
    let title: String
    let detail: String
    let state: PreflightState
    let guidance: String?
}

struct SavedScanProfile: Codable, Identifiable {
    let id: UUID
    let name: String
    let excludedPaths: [String]
    let createdAt: Date
}

struct ScanHistoryItem: Identifiable {
    let id: String
    let reportURL: URL
    let outputDirectory: URL
    let document: ScanDocument
}

enum HistoryRetentionPolicy: String, Codable, CaseIterable, Identifiable {
    case keepForever = "keep_forever"
    case days30 = "30_days"
    case days90 = "90_days"
    case days180 = "180_days"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .keepForever: "Keep all scans"
        case .days30: "Flag after 30 days"
        case .days90: "Flag after 90 days"
        case .days180: "Flag after 180 days"
        }
    }

    var ageInDays: Int? {
        switch self {
        case .keepForever: nil
        case .days30: 30
        case .days90: 90
        case .days180: 180
        }
    }
}

struct AppPreferences: Codable {
    let schemaVersion: String
    let historyRetention: HistoryRetentionPolicy

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case historyRetention = "history_retention"
    }
}

struct HistoryIndexDocument: Codable {
    let schemaVersion: String
    let generatedAt: String
    let scans: [HistoryIndexEntry]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case generatedAt = "generated_at"
        case scans
    }
}

struct HistoryIndexEntry: Codable {
    let runID: String
    let directoryName: String
    let completedAt: String
    let status: String
    let findingCount: Int
    let coverageCount: Int
    let toolIdentity: [String: String]

    enum CodingKeys: String, CodingKey {
        case runID = "run_id"
        case directoryName = "directory_name"
        case completedAt = "completed_at"
        case status
        case findingCount = "finding_count"
        case coverageCount = "coverage_count"
        case toolIdentity = "tool_identity"
    }
}

struct FindingsCatalogDocument: Decodable {
    let schemaVersion: String
    let rules: [FindingsCatalogEntry]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case rules
    }
}

struct FindingsCatalogEntry: Decodable, Identifiable {
    let id: String
    let toolID: String
    let ruleMatch: String
    let ruleValue: String
    let title: String
    let category: String
    let explanation: String
    let detectionLogic: String
    let expectedState: String
    let observedStateInterpretation: String
    let severityRationale: String
    let expectedEvidence: [String]
    let possibleFalsePositives: [String]
    let limitations: [String]
    let remediation: [String]
    let verification: [String]
    let references: [String]
    let supportedMacOS: [String]

    enum CodingKeys: String, CodingKey {
        case id
        case toolID = "tool_id"
        case ruleMatch = "rule_match"
        case ruleValue = "rule_value"
        case title
        case category
        case explanation
        case detectionLogic = "detection_logic"
        case expectedState = "expected_state"
        case observedStateInterpretation = "observed_state_interpretation"
        case severityRationale = "severity_rationale"
        case expectedEvidence = "expected_evidence"
        case possibleFalsePositives = "possible_false_positives"
        case limitations
        case remediation
        case verification
        case references
        case supportedMacOS = "supported_macos"
    }
}

struct ScanEventEnvelope: Decodable {
    let schemaVersion: String
    let sequence: UInt64
    let timestamp: String
    let type: ScanEventType
    let scanStarted: ScanStartedEvent?
    let progress: ProgressEvent?
    let commandStarted: CommandStartedEvent?
    let commandOutput: CommandOutputEvent?
    let commandCompleted: CommandCompletedEvent?
    let scanCompleted: ScanCompletedEvent?
    let scanFailed: ScanFailedEvent?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case sequence
        case timestamp
        case type
        case scanStarted = "scan_started"
        case progress
        case commandStarted = "command_started"
        case commandOutput = "command_output"
        case commandCompleted = "command_completed"
        case scanCompleted = "scan_completed"
        case scanFailed = "scan_failed"
    }
}

enum ScanEventType: String, Decodable {
    case scanStarted = "scan_started"
    case progress
    case commandStarted = "command_started"
    case commandOutput = "command_output"
    case commandCompleted = "command_completed"
    case scanCompleted = "scan_completed"
    case scanFailed = "scan_failed"
}

struct ScanStartedEvent: Decodable {
    let outputDirectory: String
    let privilegeRequested: Bool
    let excludedPaths: [String]

    enum CodingKeys: String, CodingKey {
        case outputDirectory = "output_directory"
        case privilegeRequested = "privilege_requested"
        case excludedPaths = "excluded_paths"
    }
}

struct ProgressEvent: Decodable {
    let collectorID: String
    let percent: Int
    let message: String

    enum CodingKeys: String, CodingKey {
        case collectorID = "collector_id"
        case percent
        case message
    }
}

struct EnvironmentVariable: Decodable, Hashable {
    let name: String
    let value: String
}

struct CommandStartedEvent: Decodable {
    let collectorID: String
    let commandID: String
    let executable: String
    let arguments: [String]
    let environment: [EnvironmentVariable]
    let standardInputSHA256: String?
    let standardInputBytes: Int
    let mayContainPrivateData: Bool

    enum CodingKeys: String, CodingKey {
        case collectorID = "collector_id"
        case commandID = "command_id"
        case executable
        case arguments
        case environment
        case standardInputSHA256 = "standard_input_sha256"
        case standardInputBytes = "standard_input_bytes"
        case mayContainPrivateData = "may_contain_private_data"
    }
}

struct CommandOutputEvent: Decodable {
    let collectorID: String
    let commandID: String
    let stream: String
    let data: Data
    let mayContainPrivateData: Bool

    enum CodingKeys: String, CodingKey {
        case collectorID = "collector_id"
        case commandID = "command_id"
        case stream
        case data = "data_base64"
        case mayContainPrivateData = "may_contain_private_data"
    }
}

struct CommandCompletedEvent: Decodable {
    let collectorID: String
    let commandID: String
    let exitCode: Int
    let executionError: String?

    enum CodingKeys: String, CodingKey {
        case collectorID = "collector_id"
        case commandID = "command_id"
        case exitCode = "exit_code"
        case executionError = "execution_error"
    }
}

struct ScanCompletedEvent: Decodable {
    let reportPath: String

    enum CodingKeys: String, CodingKey {
        case reportPath = "report_path"
    }
}

struct ScanFailedEvent: Decodable {
    let errorType: String
    let message: String

    enum CodingKeys: String, CodingKey {
        case errorType = "error_type"
        case message
    }
}

struct ActivityEntry: Identifiable {
    let id: UInt64
    let timestamp: String
    let collectorID: String
    let kind: String
    let summary: String
    let detail: String
    let isPrivate: Bool
    let isError: Bool
}

struct InstrumentActivity: Identifiable {
    enum State: String {
        case queued
        case running
        case completed
        case failed
        case canceled
        case notScanned = "not_scanned"
    }

    let id: String
    var name: String
    var state: State
    var detail: String
}

struct ScanDocument: Decodable {
    let schemaVersion: String
    let runID: String
    let scanner: ScannerIdentity
    let host: HostIdentity
    let startedAt: String
    let completedAt: String
    let status: String
    let privilege: PrivilegeEvidence
    let tools: [ToolRecord]
    let coverage: [CoverageRecord]
    let evidence: [EvidenceRecord]
    let findings: [FindingRecord]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case runID = "run_id"
        case scanner
        case host
        case startedAt = "started_at"
        case completedAt = "completed_at"
        case status
        case privilege
        case tools
        case coverage
        case evidence
        case findings
    }
}

struct ScannerIdentity: Decodable {
    let name: String
    let version: String
}

struct HostIdentity: Decodable {
    let hostname: String
    let operatingOS: String
    let architecture: String
    let macOSVersion: String?
    let macOSBuild: String?
    let modelID: String?
    let chip: String?

    enum CodingKeys: String, CodingKey {
        case hostname
        case operatingOS = "operating_os"
        case architecture
        case macOSVersion = "macos_version"
        case macOSBuild = "macos_build"
        case modelID = "model_id"
        case chip
    }
}

struct PrivilegeEvidence: Decodable {
    let requested: Bool
    let granted: Bool
    let collector: String
    let orchestratorEffectiveUID: Int
    let collectorEffectiveUID: Int?

    enum CodingKeys: String, CodingKey {
        case requested
        case granted
        case collector
        case orchestratorEffectiveUID = "orchestrator_effective_uid"
        case collectorEffectiveUID = "collector_effective_uid"
    }
}

struct ToolRecord: Decodable, Identifiable {
    let id: String
    let name: String
    let version: String
    let kind: String
    let origin: String?
    let executable: ExecutableIdentity?
    let data: DataIdentity?
}

struct ExecutableIdentity: Decodable {
    let path: String
    let sha256: String
}

struct DataIdentity: Decodable {
    let version: String
    let updatedAt: String
    let sha256: String

    enum CodingKeys: String, CodingKey {
        case version
        case updatedAt = "updated_at"
        case sha256
    }
}

struct CoverageRecord: Decodable, Identifiable {
    let id: String
    let collectorID: String
    let area: String
    let target: String
    let status: String
    let reason: String?
    let privilegeRequired: Bool
    let startedAt: String
    let completedAt: String

    enum CodingKeys: String, CodingKey {
        case id
        case collectorID = "collector_id"
        case area
        case target
        case status
        case reason
        case privilegeRequired = "privilege_required"
        case startedAt = "started_at"
        case completedAt = "completed_at"
    }
}

struct EvidenceRecord: Decodable, Identifiable {
    let id: String
    let collectorID: String
    let kind: String
    let observedAt: String
    let subject: String
    let summary: String
    let command: [String]?
    let artifact: ArtifactReference?

    enum CodingKeys: String, CodingKey {
        case id
        case collectorID = "collector_id"
        case kind
        case observedAt = "observed_at"
        case subject
        case summary
        case command
        case artifact
    }
}

struct ArtifactReference: Decodable {
    let path: String
    let sha256: String
    let mediaType: String

    enum CodingKeys: String, CodingKey {
        case path
        case sha256
        case mediaType = "media_type"
    }
}

struct FindingRecord: Decodable, Identifiable {
    let id: String
    let category: String
    let title: String
    let description: String
    let severity: String
    let confidence: String
    let status: String
    let firstObservedAt: String
    let sources: [SourceReference]
    let evidenceIDs: [String]
    let affectedComponents: [AffectedComponent]
    let vulnerabilities: [VulnerabilityReference]
    let remediation: RemediationRecord

    enum CodingKeys: String, CodingKey {
        case id
        case category
        case title
        case description
        case severity
        case confidence
        case status
        case firstObservedAt = "first_observed_at"
        case sources
        case evidenceIDs = "evidence_ids"
        case affectedComponents = "affected_components"
        case vulnerabilities
        case remediation
    }
}

struct SourceReference: Decodable {
    let toolID: String
    let ruleID: String
    let ruleVersion: String?

    enum CodingKeys: String, CodingKey {
        case toolID = "tool_id"
        case ruleID = "rule_id"
        case ruleVersion = "rule_version"
    }
}

struct AffectedComponent: Decodable {
    let kind: String
    let identifier: String
    let name: String
    let version: String?
    let path: String?
}

struct VulnerabilityReference: Decodable, Identifiable {
    let id: String
    let namespace: String
    let cvss: Double?
    let epss: Double?
    let knownExploited: Bool
    let url: String

    enum CodingKeys: String, CodingKey {
        case id
        case namespace
        case cvss
        case epss
        case knownExploited = "known_exploited"
        case url
    }
}

struct RemediationRecord: Decodable {
    let summary: String
    let steps: [String]
    let requiresAdmin: Bool
    let requiresRestart: Bool
    let references: [String]

    enum CodingKeys: String, CodingKey {
        case summary
        case steps
        case requiresAdmin = "requires_admin"
        case requiresRestart = "requires_restart"
        case references
    }
}
