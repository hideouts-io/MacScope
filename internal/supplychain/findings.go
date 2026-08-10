package supplychain

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"macscope/internal/model"
)

func buildVulnerabilityFindings(document GrypeDocument, database DatabaseIdentity, observedAt time.Time) ([]model.Finding, error) {
	findings := make([]model.Finding, 0, len(document.Matches))
	for index, match := range document.Matches {
		finding, err := buildVulnerabilityFinding(match, database, observedAt)
		if err != nil {
			return nil, fmt.Errorf("build Grype finding for match %d vulnerability=%q artifact=%q: %w", index, match.Vulnerability.ID, match.Artifact.ID, err)
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func buildVulnerabilityFinding(match grypeMatch, database DatabaseIdentity, observedAt time.Time) (model.Finding, error) {
	severity, err := grypeSeverity(match.Vulnerability.Severity)
	if err != nil {
		return model.Finding{}, err
	}
	confidence, matchTypes, err := grypeConfidence(match.MatchDetails)
	if err != nil {
		return model.Finding{}, err
	}
	vulnerabilityReference, err := buildVulnerabilityReference(match.Vulnerability)
	if err != nil {
		return model.Finding{}, err
	}
	affectedComponents := affectedPackageComponents(match.Artifact)
	if len(affectedComponents) == 0 {
		return model.Finding{}, fmt.Errorf("affected package components must not be empty")
	}
	identity := match.Vulnerability.ID + "\x00" + match.Artifact.ID
	digest := sha256.Sum256([]byte(identity))
	fixSummary, fixStep := remediationText(match)
	description := fmt.Sprintf("Grype matched %s %s %s to %s using %s against database %s. This indicates a package-version match, not proof that vulnerable code executed or that the Mac was compromised.", match.Artifact.Type, match.Artifact.Name, match.Artifact.Version, match.Vulnerability.ID, strings.Join(matchTypes, ", "), database.SchemaVersion)
	if strings.TrimSpace(match.Vulnerability.Description) != "" {
		description += " Advisory summary: " + strings.TrimSpace(match.Vulnerability.Description)
	}
	if confidence == model.ConfidenceMedium {
		description += " CPE-derived matches require package-identity and applicability review before remediation."
	}
	return model.Finding{
		ID:              fmt.Sprintf("finding.grype.%x", digest[:12]),
		Category:        model.FindingCategorySoftwareVulnerability,
		Title:           fmt.Sprintf("%s affects %s %s", match.Vulnerability.ID, match.Artifact.Name, match.Artifact.Version),
		Description:     description,
		Severity:        severity,
		Confidence:      confidence,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: GrypeToolID, RuleID: match.Vulnerability.ID, RuleVersion: database.SchemaVersion},
		},
		EvidenceIDs: []string{
			"evidence.grype.report",
			"evidence.grype.db-status",
			"evidence.syft.sbom",
		},
		AffectedComponents: affectedComponents,
		Vulnerabilities:    []model.VulnerabilityReference{vulnerabilityReference},
		Remediation: model.Remediation{
			Summary:         fixSummary,
			Steps:           []string{fixStep},
			RequiresAdmin:   false,
			RequiresRestart: false,
			References:      vulnerabilityReferences(match.Vulnerability, vulnerabilityReference.URL),
		},
	}, nil
}

func grypeSeverity(value string) (model.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "unknown", "negligible":
		return model.SeverityInfo, nil
	case "low":
		return model.SeverityLow, nil
	case "medium", "moderate":
		return model.SeverityMedium, nil
	case "high":
		return model.SeverityHigh, nil
	case "critical":
		return model.SeverityCritical, nil
	default:
		return "", fmt.Errorf("unsupported Grype severity %q", value)
	}
}

func grypeConfidence(details []grypeMatchDetail) (model.Confidence, []string, error) {
	seen := make(map[string]struct{}, len(details))
	matchTypes := make([]string, 0, len(details))
	confidence := model.ConfidenceHigh
	for _, detail := range details {
		matchType := strings.TrimSpace(detail.Type)
		switch matchType {
		case "exact-direct-match", "exact-indirect-match":
		case "cpe-match":
			confidence = model.ConfidenceMedium
		default:
			return "", nil, fmt.Errorf("unsupported Grype match type %q", matchType)
		}
		if _, exists := seen[matchType]; exists {
			continue
		}
		seen[matchType] = struct{}{}
		matchTypes = append(matchTypes, matchType)
	}
	return confidence, matchTypes, nil
}

func buildVulnerabilityReference(vulnerability grypeVulnerability) (model.VulnerabilityReference, error) {
	namespace, referenceURL, err := vulnerabilityIdentity(vulnerability)
	if err != nil {
		return model.VulnerabilityReference{}, err
	}
	return model.VulnerabilityReference{
		ID:             vulnerability.ID,
		Namespace:      namespace,
		CVSS:           maximumCVSS(vulnerability.CVSS),
		EPSS:           matchingEPSS(vulnerability),
		KnownExploited: false,
		URL:            referenceURL,
	}, nil
}

func vulnerabilityIdentity(vulnerability grypeVulnerability) (model.VulnerabilityNamespace, string, error) {
	identifier := strings.TrimSpace(vulnerability.ID)
	switch {
	case strings.HasPrefix(identifier, "CVE-"):
		return model.VulnerabilityNamespaceCVE, "https://nvd.nist.gov/vuln/detail/" + identifier, nil
	case strings.HasPrefix(identifier, "GHSA-"):
		return model.VulnerabilityNamespaceGHSA, "https://github.com/advisories/" + identifier, nil
	default:
		if err := requireHTTPSURL("Grype vulnerability data source", vulnerability.DataSource); err != nil {
			return "", "", err
		}
		return model.VulnerabilityNamespaceOSV, vulnerability.DataSource, nil
	}
}

func maximumCVSS(records []grypeCVSS) *float64 {
	if len(records) == 0 {
		return nil
	}
	maximum := records[0].Metrics.BaseScore
	for _, record := range records[1:] {
		if record.Metrics.BaseScore > maximum {
			maximum = record.Metrics.BaseScore
		}
	}
	value := maximum
	return &value
}

func matchingEPSS(vulnerability grypeVulnerability) *float64 {
	if !strings.HasPrefix(vulnerability.ID, "CVE-") {
		return nil
	}
	found := false
	maximum := 0.0
	for _, record := range vulnerability.EPSS {
		if record.CVE != vulnerability.ID {
			continue
		}
		if !found || record.EPSS > maximum {
			maximum = record.EPSS
			found = true
		}
	}
	if !found {
		return nil
	}
	value := maximum
	return &value
}

func affectedPackageComponents(item grypeArtifact) []model.AffectedComponent {
	identifier := strings.TrimSpace(item.PURL)
	if identifier == "" {
		identifier = item.Type + ":" + item.Name
	}
	if len(item.Locations) == 0 {
		return []model.AffectedComponent{{
			Kind:       model.AffectedComponentPackage,
			Identifier: identifier,
			Name:       item.Name,
			Version:    item.Version,
		}}
	}
	components := make([]model.AffectedComponent, 0, len(item.Locations))
	seenPaths := make(map[string]struct{}, len(item.Locations))
	for _, location := range item.Locations {
		absolutePath := rootLocationToAbsolute(location.Path)
		if _, exists := seenPaths[absolutePath]; exists {
			continue
		}
		seenPaths[absolutePath] = struct{}{}
		components = append(components, model.AffectedComponent{
			Kind:       model.AffectedComponentPackage,
			Identifier: identifier,
			Name:       item.Name,
			Version:    item.Version,
			Path:       absolutePath,
		})
	}
	return components
}

func remediationText(match grypeMatch) (string, string) {
	if len(match.Vulnerability.Fix.Versions) > 0 {
		versions := strings.Join(match.Vulnerability.Fix.Versions, ", ")
		return fmt.Sprintf("Update %s to a fixed release after confirming the owning application or package manager.", match.Artifact.Name), fmt.Sprintf("Locate the software that owns %s and update %s from %s to an applicable fixed version: %s.", primaryLocation(match.Artifact), match.Artifact.Name, match.Artifact.Version, versions)
	}
	return fmt.Sprintf("Review %s applicability and remove, replace, or isolate the affected component when no fixed version is listed.", match.Vulnerability.ID), fmt.Sprintf("Confirm that %s at %s is used at runtime, then follow the upstream advisory because Grype lists fix state %q without a fixed version.", match.Artifact.Name, primaryLocation(match.Artifact), match.Vulnerability.Fix.State)
}

func primaryLocation(item grypeArtifact) string {
	if len(item.Locations) == 0 {
		return "an unlocated SBOM package entry"
	}
	return rootLocationToAbsolute(item.Locations[0].Path)
}

func rootLocationToAbsolute(path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(string(filepath.Separator), path)
}

func vulnerabilityReferences(vulnerability grypeVulnerability, primary string) []string {
	references := []string{primary}
	seen := map[string]struct{}{primary: {}}
	candidates := append([]string{vulnerability.DataSource}, vulnerability.URLs...)
	for _, candidate := range candidates {
		if requireHTTPSURL("Grype vulnerability reference", candidate) != nil {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		references = append(references, candidate)
	}
	return references
}

func buildToolErrorFinding(toolID string, ruleID string, title string, cause error, observedAt time.Time, evidenceIDs []string, affectedPath string, reference string) model.Finding {
	return model.Finding{
		ID:              "finding." + toolID + "." + ruleID + ".tool-error",
		Category:        model.FindingCategoryToolError,
		Title:           title,
		Description:     cause.Error(),
		Severity:        model.SeverityLow,
		Confidence:      model.ConfidenceConfirmed,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: "macscope", RuleID: toolID + "." + ruleID, RuleVersion: "1"},
		},
		EvidenceIDs: append([]string(nil), evidenceIDs...),
		AffectedComponents: []model.AffectedComponent{
			{Kind: model.AffectedComponentScanner, Identifier: "macscope." + toolID, Name: toolID + " adapter", Path: affectedPath},
		},
		Vulnerabilities: make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         "Resolve the reported tool provenance, database, execution, or output-validation error, then run a new scan.",
			Steps:           []string{"Inspect the preserved command evidence and tools.lock.json before retrying the scan."},
			RequiresAdmin:   false,
			RequiresRestart: false,
			References:      []string{reference},
		},
	}
}

func buildCoverageGapFinding(identifier string, title string, reason string, observedAt time.Time, evidenceID string) model.Finding {
	return model.Finding{
		ID:              "finding.supply-chain." + identifier + ".coverage-gap",
		Category:        model.FindingCategoryCoverageGap,
		Title:           title,
		Description:     reason + ". No dependency-vulnerability conclusion was produced.",
		Severity:        model.SeverityInfo,
		Confidence:      model.ConfidenceConfirmed,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: "macscope", RuleID: "supply-chain.coverage", RuleVersion: "1"},
		},
		EvidenceIDs: []string{evidenceID},
		AffectedComponents: []model.AffectedComponent{
			{Kind: model.AffectedComponentScanner, Identifier: "macscope.supply-chain", Name: "Syft and Grype adapter"},
		},
		Vulnerabilities: make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         "Restore validated Syft SBOM generation and Grype matching, then run a new scan.",
			Steps:           []string{"Inspect the referenced evidence, install the pinned tools from tools.lock.json if necessary, and retry using a new output directory."},
			RequiresAdmin:   false,
			RequiresRestart: false,
			References:      []string{SyftOriginURL, GrypeOriginURL},
		},
	}
}
