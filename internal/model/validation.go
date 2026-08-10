package model

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$`)
	sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	cvePattern    = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	ghsaPattern   = regexp.MustCompile(`^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$`)
	osvPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$`)
)

type ValidationError struct {
	Path    string
	Message string
}

func (err ValidationError) Error() string {
	return fmt.Sprintf("validate scan document at %s: %s", err.Path, err.Message)
}

func ValidateScanRun(run ScanRun) error {
	if run.SchemaVersion != ScanSchemaVersion {
		return newValidationError("schema_version", fmt.Sprintf("value %q is unsupported; expected %q", run.SchemaVersion, ScanSchemaVersion))
	}
	if err := validateID("run_id", run.RunID); err != nil {
		return err
	}
	if err := validateScanner(run.Scanner); err != nil {
		return err
	}
	if err := validateHost(run.Host); err != nil {
		return err
	}
	if err := validateTimestamp("started_at", run.StartedAt); err != nil {
		return err
	}
	if err := validateTimestamp("completed_at", run.CompletedAt); err != nil {
		return err
	}
	if run.CompletedAt.Before(run.StartedAt) {
		return newValidationError("completed_at", fmt.Sprintf("timestamp %s precedes started_at %s", run.CompletedAt.Format(time.RFC3339Nano), run.StartedAt.Format(time.RFC3339Nano)))
	}
	if err := validateRunStatus(run.Status); err != nil {
		return err
	}
	if err := validatePrivilege(run.Privilege); err != nil {
		return err
	}
	if run.Tools == nil {
		return newValidationError("tools", "array must not be null")
	}
	if len(run.Tools) == 0 {
		return newValidationError("tools", "at least one tool record is required")
	}
	if run.Coverage == nil {
		return newValidationError("coverage", "array must not be null")
	}
	if run.Evidence == nil {
		return newValidationError("evidence", "array must not be null")
	}
	if run.Findings == nil {
		return newValidationError("findings", "array must not be null")
	}

	toolIDs, err := validateTools(run.Tools, run.Scanner, run.CompletedAt)
	if err != nil {
		return err
	}
	if err := validateCoverage(run.Coverage, toolIDs, run.StartedAt, run.CompletedAt); err != nil {
		return err
	}
	evidenceIDs, err := validateEvidence(run.Evidence, toolIDs, run.StartedAt, run.CompletedAt)
	if err != nil {
		return err
	}
	if err := validateFindings(run.Findings, toolIDs, evidenceIDs, run.StartedAt, run.CompletedAt); err != nil {
		return err
	}
	return nil
}

func validateScanner(scanner ScannerIdentity) error {
	if err := validateRequired("scanner.name", scanner.Name); err != nil {
		return err
	}
	return validateRequired("scanner.version", scanner.Version)
}

func validateHost(host HostIdentity) error {
	if err := validateRequired("host.hostname", host.Hostname); err != nil {
		return err
	}
	if host.OperatingOS != "darwin" {
		return newValidationError("host.operating_os", fmt.Sprintf("value %q is unsupported; MacScope requires darwin", host.OperatingOS))
	}
	return validateRequired("host.architecture", host.Architecture)
}

func validateRunStatus(status RunStatus) error {
	switch status {
	case RunStatusCompleted, RunStatusPartial, RunStatusFailed:
		return nil
	default:
		return newValidationError("status", fmt.Sprintf("value %q is not a supported run status", status))
	}
}

func validatePrivilege(privilegeEvidence PrivilegeEvidence) error {
	if privilegeEvidence.OrchestratorEffectiveUID <= 0 {
		return newValidationError("privilege.orchestrator_effective_uid", fmt.Sprintf("value %d is invalid; the orchestrator must run as a non-root user", privilegeEvidence.OrchestratorEffectiveUID))
	}
	if !privilegeEvidence.Requested {
		if privilegeEvidence.Granted {
			return newValidationError("privilege.granted", "cannot be true when privilege was not requested")
		}
		if privilegeEvidence.Collector != "none" {
			return newValidationError("privilege.collector", "value must be \"none\" when privilege was not requested")
		}
		if privilegeEvidence.CollectorEffectiveUID != nil {
			return newValidationError("privilege.collector_effective_uid", "must be absent when privilege was not requested")
		}
		return nil
	}

	if !privilegeEvidence.Granted {
		return newValidationError("privilege.granted", "must be true in a completed document when privilege was requested; authorization failures stop the scan")
	}
	if privilegeEvidence.Collector == "" || privilegeEvidence.Collector == "none" {
		return newValidationError("privilege.collector", "a privileged collector name is required when authorization is granted")
	}
	if privilegeEvidence.CollectorEffectiveUID == nil {
		return newValidationError("privilege.collector_effective_uid", "is required when authorization is granted")
	}
	if *privilegeEvidence.CollectorEffectiveUID != 0 {
		return newValidationError("privilege.collector_effective_uid", fmt.Sprintf("value %d is invalid; expected root effective UID 0", *privilegeEvidence.CollectorEffectiveUID))
	}
	return nil
}

func validateTools(tools []ToolRecord, scanner ScannerIdentity, runCompletedAt time.Time) (map[string]struct{}, error) {
	toolIDs := make(map[string]struct{}, len(tools))
	matchingScannerFound := false
	for index, tool := range tools {
		pathPrefix := fmt.Sprintf("tools[%d]", index)
		if err := validateID(pathPrefix+".id", tool.ID); err != nil {
			return nil, err
		}
		if _, exists := toolIDs[tool.ID]; exists {
			return nil, newValidationError(pathPrefix+".id", fmt.Sprintf("duplicate tool ID %q", tool.ID))
		}
		toolIDs[tool.ID] = struct{}{}
		if err := validateRequired(pathPrefix+".name", tool.Name); err != nil {
			return nil, err
		}
		if err := validateRequired(pathPrefix+".version", tool.Version); err != nil {
			return nil, err
		}
		if err := validateToolKind(pathPrefix+".kind", tool.Kind); err != nil {
			return nil, err
		}
		if tool.Kind == ToolKindScanner && tool.Name == scanner.Name && tool.Version == scanner.Version {
			matchingScannerFound = true
		}
		if tool.Origin != "" {
			if err := validateHTTPSURL(pathPrefix+".origin", tool.Origin); err != nil {
				return nil, err
			}
		}
		if tool.Executable == nil && tool.Data == nil {
			return nil, newValidationError(pathPrefix, "tool provenance requires executable or data identity")
		}
		if tool.Kind == ToolKindFeed && tool.Data == nil {
			return nil, newValidationError(pathPrefix+".data", "data identity is required for a feed tool")
		}
		if tool.Executable != nil {
			if !filepath.IsAbs(tool.Executable.Path) {
				return nil, newValidationError(pathPrefix+".executable.path", fmt.Sprintf("path %q must be absolute", tool.Executable.Path))
			}
			if err := validateSHA256(pathPrefix+".executable.sha256", tool.Executable.SHA256); err != nil {
				return nil, err
			}
		}
		if tool.Data != nil {
			if err := validateRequired(pathPrefix+".data.version", tool.Data.Version); err != nil {
				return nil, err
			}
			if err := validateTimestamp(pathPrefix+".data.updated_at", tool.Data.UpdatedAt); err != nil {
				return nil, err
			}
			if tool.Data.UpdatedAt.After(runCompletedAt) {
				return nil, newValidationError(pathPrefix+".data.updated_at", "data timestamp must not be later than the completed scan")
			}
			if err := validateSHA256(pathPrefix+".data.sha256", tool.Data.SHA256); err != nil {
				return nil, err
			}
		}
	}
	if !matchingScannerFound {
		return nil, newValidationError("tools", fmt.Sprintf("a scanner tool matching scanner name %q and version %q is required", scanner.Name, scanner.Version))
	}
	return toolIDs, nil
}

func validateToolKind(path string, kind ToolKind) error {
	switch kind {
	case ToolKindScanner, ToolKindCollector, ToolKindFeed, ToolKindMatcher:
		return nil
	default:
		return newValidationError(path, fmt.Sprintf("value %q is not a supported tool kind", kind))
	}
}

func validateCoverage(records []CoverageRecord, toolIDs map[string]struct{}, runStartedAt time.Time, runCompletedAt time.Time) error {
	coverageIDs := make(map[string]struct{}, len(records))
	for index, record := range records {
		pathPrefix := fmt.Sprintf("coverage[%d]", index)
		if err := validateID(pathPrefix+".id", record.ID); err != nil {
			return err
		}
		if _, exists := coverageIDs[record.ID]; exists {
			return newValidationError(pathPrefix+".id", fmt.Sprintf("duplicate coverage ID %q", record.ID))
		}
		coverageIDs[record.ID] = struct{}{}
		if _, exists := toolIDs[record.CollectorID]; !exists {
			return newValidationError(pathPrefix+".collector_id", fmt.Sprintf("references unknown tool ID %q", record.CollectorID))
		}
		if err := validateCoverageArea(pathPrefix+".area", record.Area); err != nil {
			return err
		}
		if err := validateRequired(pathPrefix+".target", record.Target); err != nil {
			return err
		}
		if err := validateCoverageStatus(pathPrefix+".status", record.Status); err != nil {
			return err
		}
		if record.Status != CoverageStatusComplete && strings.TrimSpace(record.Reason) == "" {
			return newValidationError(pathPrefix+".reason", fmt.Sprintf("is required when coverage status is %q", record.Status))
		}
		if err := validateInterval(pathPrefix, record.StartedAt, record.CompletedAt, runStartedAt, runCompletedAt); err != nil {
			return err
		}
	}
	return nil
}

func validateCoverageArea(path string, area CoverageArea) error {
	switch area {
	case CoverageAreaHostIdentity,
		CoverageAreaAppleUpdates,
		CoverageAreaSecurityControls,
		CoverageAreaPersistence,
		CoverageAreaNetworkExposure,
		CoverageAreaInstalledSoftware,
		CoverageAreaDependencyVulnerabilities,
		CoverageAreaThreatIndicators:
		return nil
	default:
		return newValidationError(path, fmt.Sprintf("value %q is not a supported coverage area", area))
	}
}

func validateCoverageStatus(path string, status CoverageStatus) error {
	switch status {
	case CoverageStatusComplete, CoverageStatusPartial, CoverageStatusNotScanned, CoverageStatusFailed:
		return nil
	default:
		return newValidationError(path, fmt.Sprintf("value %q is not a supported coverage status", status))
	}
}

func validateEvidence(records []EvidenceRecord, toolIDs map[string]struct{}, runStartedAt time.Time, runCompletedAt time.Time) (map[string]struct{}, error) {
	evidenceIDs := make(map[string]struct{}, len(records))
	for index, record := range records {
		pathPrefix := fmt.Sprintf("evidence[%d]", index)
		if err := validateID(pathPrefix+".id", record.ID); err != nil {
			return nil, err
		}
		if _, exists := evidenceIDs[record.ID]; exists {
			return nil, newValidationError(pathPrefix+".id", fmt.Sprintf("duplicate evidence ID %q", record.ID))
		}
		evidenceIDs[record.ID] = struct{}{}
		if _, exists := toolIDs[record.CollectorID]; !exists {
			return nil, newValidationError(pathPrefix+".collector_id", fmt.Sprintf("references unknown tool ID %q", record.CollectorID))
		}
		if err := validateEvidenceKind(pathPrefix+".kind", record.Kind); err != nil {
			return nil, err
		}
		if err := validateTimestamp(pathPrefix+".observed_at", record.ObservedAt); err != nil {
			return nil, err
		}
		if record.ObservedAt.Before(runStartedAt) || record.ObservedAt.After(runCompletedAt) {
			return nil, newValidationError(pathPrefix+".observed_at", "timestamp must fall within the scan interval")
		}
		if err := validateRequired(pathPrefix+".subject", record.Subject); err != nil {
			return nil, err
		}
		if err := validateRequired(pathPrefix+".summary", record.Summary); err != nil {
			return nil, err
		}
		if record.Kind == EvidenceKindCommandOutput && len(record.Command) == 0 {
			return nil, newValidationError(pathPrefix+".command", "at least one command argument is required for command output evidence")
		}
		for argumentIndex, argument := range record.Command {
			if strings.TrimSpace(argument) == "" {
				return nil, newValidationError(fmt.Sprintf("%s.command[%d]", pathPrefix, argumentIndex), "command argument must not be empty")
			}
		}
		if record.Kind == EvidenceKindAPIResponse && record.Artifact == nil {
			return nil, newValidationError(pathPrefix+".artifact", "is required for API response evidence")
		}
		if record.Artifact != nil {
			if err := validateArtifact(pathPrefix+".artifact", *record.Artifact); err != nil {
				return nil, err
			}
		}
	}
	return evidenceIDs, nil
}

func validateEvidenceKind(path string, kind EvidenceKind) error {
	switch kind {
	case EvidenceKindCommandOutput, EvidenceKindAPIResponse, EvidenceKindFileMetadata, EvidenceKindObservation:
		return nil
	default:
		return newValidationError(path, fmt.Sprintf("value %q is not a supported evidence kind", kind))
	}
}

func validateArtifact(pathPrefix string, artifact ArtifactReference) error {
	if filepath.IsAbs(artifact.Path) {
		return newValidationError(pathPrefix+".path", fmt.Sprintf("artifact path %q must be relative to the scan output directory", artifact.Path))
	}
	cleanPath := filepath.Clean(artifact.Path)
	if cleanPath == "." || cleanPath != artifact.Path || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
		return newValidationError(pathPrefix+".path", fmt.Sprintf("artifact path %q is not a clean in-report path", artifact.Path))
	}
	if err := validateSHA256(pathPrefix+".sha256", artifact.SHA256); err != nil {
		return err
	}
	if !strings.Contains(artifact.MediaType, "/") {
		return newValidationError(pathPrefix+".media_type", fmt.Sprintf("value %q is not a valid media type", artifact.MediaType))
	}
	return nil
}

func validateFindings(findings []Finding, toolIDs map[string]struct{}, evidenceIDs map[string]struct{}, runStartedAt time.Time, runCompletedAt time.Time) error {
	findingIDs := make(map[string]struct{}, len(findings))
	for index, finding := range findings {
		pathPrefix := fmt.Sprintf("findings[%d]", index)
		if err := validateID(pathPrefix+".id", finding.ID); err != nil {
			return err
		}
		if _, exists := findingIDs[finding.ID]; exists {
			return newValidationError(pathPrefix+".id", fmt.Sprintf("duplicate finding ID %q", finding.ID))
		}
		findingIDs[finding.ID] = struct{}{}
		if err := validateFindingCategory(pathPrefix+".category", finding.Category); err != nil {
			return err
		}
		if err := validateRequired(pathPrefix+".title", finding.Title); err != nil {
			return err
		}
		if err := validateRequired(pathPrefix+".description", finding.Description); err != nil {
			return err
		}
		if err := validateSeverity(pathPrefix+".severity", finding.Severity); err != nil {
			return err
		}
		if err := validateConfidence(pathPrefix+".confidence", finding.Confidence); err != nil {
			return err
		}
		if err := validateFindingStatus(pathPrefix+".status", finding.Status); err != nil {
			return err
		}
		if err := validateTimestamp(pathPrefix+".first_observed_at", finding.FirstObservedAt); err != nil {
			return err
		}
		if finding.FirstObservedAt.Before(runStartedAt) || finding.FirstObservedAt.After(runCompletedAt) {
			return newValidationError(pathPrefix+".first_observed_at", "timestamp must fall within the scan interval")
		}
		if err := validateSources(pathPrefix+".sources", finding.Sources, toolIDs); err != nil {
			return err
		}
		if err := validateEvidenceReferences(pathPrefix+".evidence_ids", finding.EvidenceIDs, evidenceIDs); err != nil {
			return err
		}
		if err := validateAffectedComponents(pathPrefix+".affected_components", finding.AffectedComponents); err != nil {
			return err
		}
		if err := validateVulnerabilities(pathPrefix+".vulnerabilities", finding.Category, finding.Vulnerabilities); err != nil {
			return err
		}
		if err := validateRemediation(pathPrefix+".remediation", finding.Remediation); err != nil {
			return err
		}
	}
	return nil
}

func validateFindingCategory(path string, category FindingCategory) error {
	switch category {
	case FindingCategoryOSVulnerability,
		FindingCategorySoftwareVulnerability,
		FindingCategoryConfiguration,
		FindingCategoryNetworkExposure,
		FindingCategoryPersistence,
		FindingCategoryThreatIndicator,
		FindingCategoryCoverageGap,
		FindingCategoryToolError:
		return nil
	default:
		return newValidationError(path, fmt.Sprintf("value %q is not a supported finding category", category))
	}
}

func validateSeverity(path string, severity Severity) error {
	switch severity {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return nil
	default:
		return newValidationError(path, fmt.Sprintf("value %q is not a supported severity", severity))
	}
}

func validateConfidence(path string, confidence Confidence) error {
	switch confidence {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh, ConfidenceConfirmed:
		return nil
	default:
		return newValidationError(path, fmt.Sprintf("value %q is not a supported confidence", confidence))
	}
}

func validateFindingStatus(path string, status FindingStatus) error {
	switch status {
	case FindingStatusDetected:
		return nil
	default:
		return newValidationError(path, fmt.Sprintf("value %q is not a supported finding status", status))
	}
}

func validateSources(pathPrefix string, sources []SourceReference, toolIDs map[string]struct{}) error {
	if len(sources) == 0 {
		return newValidationError(pathPrefix, "at least one source reference is required")
	}
	seenSources := make(map[string]struct{}, len(sources))
	for index, source := range sources {
		itemPath := fmt.Sprintf("%s[%d]", pathPrefix, index)
		if _, exists := toolIDs[source.ToolID]; !exists {
			return newValidationError(itemPath+".tool_id", fmt.Sprintf("references unknown tool ID %q", source.ToolID))
		}
		if err := validateRequired(itemPath+".rule_id", source.RuleID); err != nil {
			return err
		}
		identity := source.ToolID + "\x00" + source.RuleID + "\x00" + source.RuleVersion
		if _, exists := seenSources[identity]; exists {
			return newValidationError(itemPath, fmt.Sprintf("duplicate source reference for tool %q rule %q version %q", source.ToolID, source.RuleID, source.RuleVersion))
		}
		seenSources[identity] = struct{}{}
	}
	return nil
}

func validateEvidenceReferences(pathPrefix string, references []string, evidenceIDs map[string]struct{}) error {
	if len(references) == 0 {
		return newValidationError(pathPrefix, "at least one evidence reference is required")
	}
	seenReferences := make(map[string]struct{}, len(references))
	for index, evidenceID := range references {
		itemPath := fmt.Sprintf("%s[%d]", pathPrefix, index)
		if _, exists := evidenceIDs[evidenceID]; !exists {
			return newValidationError(itemPath, fmt.Sprintf("references unknown evidence ID %q", evidenceID))
		}
		if _, exists := seenReferences[evidenceID]; exists {
			return newValidationError(itemPath, fmt.Sprintf("duplicate evidence reference %q", evidenceID))
		}
		seenReferences[evidenceID] = struct{}{}
	}
	return nil
}

func validateAffectedComponents(pathPrefix string, components []AffectedComponent) error {
	if len(components) == 0 {
		return newValidationError(pathPrefix, "at least one affected component is required")
	}
	seenComponents := make(map[string]struct{}, len(components))
	for index, component := range components {
		itemPath := fmt.Sprintf("%s[%d]", pathPrefix, index)
		if err := validateAffectedComponentKind(itemPath+".kind", component.Kind); err != nil {
			return err
		}
		if err := validateRequired(itemPath+".identifier", component.Identifier); err != nil {
			return err
		}
		if err := validateRequired(itemPath+".name", component.Name); err != nil {
			return err
		}
		if component.Path != "" && !filepath.IsAbs(component.Path) {
			return newValidationError(itemPath+".path", fmt.Sprintf("affected component path %q must be absolute", component.Path))
		}
		identity := string(component.Kind) + "\x00" + component.Identifier + "\x00" + component.Version + "\x00" + component.Path
		if _, exists := seenComponents[identity]; exists {
			return newValidationError(itemPath, fmt.Sprintf("duplicate affected component %q", component.Identifier))
		}
		seenComponents[identity] = struct{}{}
	}
	return nil
}

func validateAffectedComponentKind(path string, kind AffectedComponentKind) error {
	switch kind {
	case AffectedComponentOS,
		AffectedComponentApplication,
		AffectedComponentPackage,
		AffectedComponentFile,
		AffectedComponentProcess,
		AffectedComponentService,
		AffectedComponentPort,
		AffectedComponentConfiguration,
		AffectedComponentScanner:
		return nil
	default:
		return newValidationError(path, fmt.Sprintf("value %q is not a supported affected component kind", kind))
	}
}

func validateVulnerabilities(pathPrefix string, category FindingCategory, vulnerabilities []VulnerabilityReference) error {
	if vulnerabilities == nil {
		return newValidationError(pathPrefix, "array must not be null")
	}
	if (category == FindingCategoryOSVulnerability || category == FindingCategorySoftwareVulnerability) && len(vulnerabilities) == 0 {
		return newValidationError(pathPrefix, "at least one CVE reference is required for vulnerability findings")
	}
	seenVulnerabilities := make(map[string]struct{}, len(vulnerabilities))
	for index, vulnerability := range vulnerabilities {
		itemPath := fmt.Sprintf("%s[%d]", pathPrefix, index)
		if err := validateVulnerabilityID(itemPath, vulnerability.Namespace, vulnerability.ID); err != nil {
			return err
		}
		identity := string(vulnerability.Namespace) + "\x00" + vulnerability.ID
		if _, exists := seenVulnerabilities[identity]; exists {
			return newValidationError(itemPath+".id", fmt.Sprintf("duplicate vulnerability reference %q in namespace %q", vulnerability.ID, vulnerability.Namespace))
		}
		seenVulnerabilities[identity] = struct{}{}
		if vulnerability.CVSS != nil && (*vulnerability.CVSS < 0 || *vulnerability.CVSS > 10) {
			return newValidationError(itemPath+".cvss", fmt.Sprintf("value %v must be between 0 and 10", *vulnerability.CVSS))
		}
		if vulnerability.EPSS != nil && (*vulnerability.EPSS < 0 || *vulnerability.EPSS > 1) {
			return newValidationError(itemPath+".epss", fmt.Sprintf("value %v must be between 0 and 1", *vulnerability.EPSS))
		}
		if vulnerability.EPSS != nil && vulnerability.Namespace != VulnerabilityNamespaceCVE {
			return newValidationError(itemPath+".epss", "EPSS is supported only for CVE references")
		}
		if vulnerability.KnownExploited && vulnerability.Namespace != VulnerabilityNamespaceCVE {
			return newValidationError(itemPath+".known_exploited", "known-exploited status is supported only for CVE references")
		}
		if err := validateHTTPSURL(itemPath+".url", vulnerability.URL); err != nil {
			return err
		}
	}
	return nil
}

func validateVulnerabilityID(pathPrefix string, namespace VulnerabilityNamespace, identifier string) error {
	var pattern *regexp.Regexp
	switch namespace {
	case VulnerabilityNamespaceCVE:
		pattern = cvePattern
	case VulnerabilityNamespaceGHSA:
		pattern = ghsaPattern
	case VulnerabilityNamespaceOSV:
		pattern = osvPattern
	default:
		return newValidationError(pathPrefix+".namespace", fmt.Sprintf("value %q is not a supported vulnerability namespace", namespace))
	}
	if !pattern.MatchString(identifier) {
		return newValidationError(pathPrefix+".id", fmt.Sprintf("value %q is invalid for vulnerability namespace %q", identifier, namespace))
	}
	return nil
}

func validateRemediation(pathPrefix string, remediation Remediation) error {
	if err := validateRequired(pathPrefix+".summary", remediation.Summary); err != nil {
		return err
	}
	if len(remediation.Steps) == 0 {
		return newValidationError(pathPrefix+".steps", "at least one remediation step is required")
	}
	if remediation.References == nil {
		return newValidationError(pathPrefix+".references", "array must not be null")
	}
	for index, step := range remediation.Steps {
		if strings.TrimSpace(step) == "" {
			return newValidationError(fmt.Sprintf("%s.steps[%d]", pathPrefix, index), "remediation step must not be empty")
		}
	}
	for index, reference := range remediation.References {
		if err := validateHTTPSURL(fmt.Sprintf("%s.references[%d]", pathPrefix, index), reference); err != nil {
			return err
		}
	}
	return nil
}

func validateInterval(pathPrefix string, startedAt time.Time, completedAt time.Time, runStartedAt time.Time, runCompletedAt time.Time) error {
	if err := validateTimestamp(pathPrefix+".started_at", startedAt); err != nil {
		return err
	}
	if err := validateTimestamp(pathPrefix+".completed_at", completedAt); err != nil {
		return err
	}
	if completedAt.Before(startedAt) {
		return newValidationError(pathPrefix+".completed_at", "timestamp precedes collector started_at")
	}
	if startedAt.Before(runStartedAt) || completedAt.After(runCompletedAt) {
		return newValidationError(pathPrefix, "collector interval must fall within the scan interval")
	}
	return nil
}

func validateTimestamp(path string, value time.Time) error {
	if value.IsZero() {
		return newValidationError(path, "timestamp is required")
	}
	_, offset := value.Zone()
	if offset != 0 {
		return newValidationError(path, "timestamp must use UTC offset zero")
	}
	return nil
}

func validateID(path string, value string) error {
	if !idPattern.MatchString(value) {
		return newValidationError(path, fmt.Sprintf("value %q must match %s", value, idPattern.String()))
	}
	return nil
}

func validateRequired(path string, value string) error {
	if strings.TrimSpace(value) == "" {
		return newValidationError(path, "value is required")
	}
	return nil
}

func validateSHA256(path string, value string) error {
	if !sha256Pattern.MatchString(value) {
		return newValidationError(path, fmt.Sprintf("value %q must be a lowercase 64-character SHA-256 digest", value))
	}
	return nil
}

func validateHTTPSURL(path string, value string) error {
	parsedURL, err := url.ParseRequestURI(value)
	if err != nil {
		return newValidationError(path, fmt.Sprintf("value %q is not a valid URL: %v", value, err))
	}
	if parsedURL.Scheme != "https" || parsedURL.Host == "" {
		return newValidationError(path, fmt.Sprintf("URL %q must use HTTPS and include a host", value))
	}
	return nil
}

func newValidationError(path string, message string) ValidationError {
	return ValidationError{
		Path:    path,
		Message: message,
	}
}
