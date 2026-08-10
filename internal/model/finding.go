package model

import "time"

type FindingCategory string

const (
	FindingCategoryOSVulnerability       FindingCategory = "os_vulnerability"
	FindingCategorySoftwareVulnerability FindingCategory = "software_vulnerability"
	FindingCategoryConfiguration         FindingCategory = "configuration"
	FindingCategoryNetworkExposure       FindingCategory = "network_exposure"
	FindingCategoryPersistence           FindingCategory = "persistence"
	FindingCategoryThreatIndicator       FindingCategory = "threat_indicator"
	FindingCategoryCoverageGap           FindingCategory = "coverage_gap"
	FindingCategoryToolError             FindingCategory = "tool_error"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Confidence string

const (
	ConfidenceLow       Confidence = "low"
	ConfidenceMedium    Confidence = "medium"
	ConfidenceHigh      Confidence = "high"
	ConfidenceConfirmed Confidence = "confirmed"
)

type FindingStatus string

const (
	FindingStatusDetected FindingStatus = "detected"
)

type AffectedComponentKind string

const (
	AffectedComponentOS            AffectedComponentKind = "operating_system"
	AffectedComponentApplication   AffectedComponentKind = "application"
	AffectedComponentPackage       AffectedComponentKind = "package"
	AffectedComponentFile          AffectedComponentKind = "file"
	AffectedComponentProcess       AffectedComponentKind = "process"
	AffectedComponentService       AffectedComponentKind = "service"
	AffectedComponentPort          AffectedComponentKind = "port"
	AffectedComponentConfiguration AffectedComponentKind = "configuration"
	AffectedComponentScanner       AffectedComponentKind = "scanner"
)

type SourceReference struct {
	ToolID      string `json:"tool_id"`
	RuleID      string `json:"rule_id"`
	RuleVersion string `json:"rule_version,omitempty"`
}

type AffectedComponent struct {
	Kind       AffectedComponentKind `json:"kind"`
	Identifier string                `json:"identifier"`
	Name       string                `json:"name"`
	Version    string                `json:"version,omitempty"`
	Path       string                `json:"path,omitempty"`
}

type VulnerabilityNamespace string

const (
	VulnerabilityNamespaceCVE  VulnerabilityNamespace = "cve"
	VulnerabilityNamespaceGHSA VulnerabilityNamespace = "ghsa"
	VulnerabilityNamespaceOSV  VulnerabilityNamespace = "osv"
)

type VulnerabilityReference struct {
	ID             string                 `json:"id"`
	Namespace      VulnerabilityNamespace `json:"namespace"`
	CVSS           *float64               `json:"cvss,omitempty"`
	EPSS           *float64               `json:"epss,omitempty"`
	KnownExploited bool                   `json:"known_exploited"`
	URL            string                 `json:"url"`
}

type Remediation struct {
	Summary         string   `json:"summary"`
	Steps           []string `json:"steps"`
	RequiresAdmin   bool     `json:"requires_admin"`
	RequiresRestart bool     `json:"requires_restart"`
	References      []string `json:"references"`
}

type Finding struct {
	ID                 string                   `json:"id"`
	Category           FindingCategory          `json:"category"`
	Title              string                   `json:"title"`
	Description        string                   `json:"description"`
	Severity           Severity                 `json:"severity"`
	Confidence         Confidence               `json:"confidence"`
	Status             FindingStatus            `json:"status"`
	FirstObservedAt    time.Time                `json:"first_observed_at"`
	Sources            []SourceReference        `json:"sources"`
	EvidenceIDs        []string                 `json:"evidence_ids"`
	AffectedComponents []AffectedComponent      `json:"affected_components"`
	Vulnerabilities    []VulnerabilityReference `json:"vulnerabilities"`
	Remediation        Remediation              `json:"remediation"`
}
