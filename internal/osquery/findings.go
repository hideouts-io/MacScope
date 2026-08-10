package osquery

import (
	"fmt"
	"time"

	"macscope/internal/model"
	"macscope/internal/mscp"
)

func buildComplianceFinding(rule mscp.Rule, observedValue string, observedAt time.Time, evidenceID string) model.Finding {
	return model.Finding{
		ID:              "finding.mscp." + rule.ID,
		Category:        model.FindingCategoryConfiguration,
		Title:           rule.Title,
		Description:     fmt.Sprintf("%s osquery observed value %q; expected one of %v. This is a configuration-posture finding and does not by itself indicate compromise.", rule.Description, observedValue, rule.ExpectedValues),
		Severity:        rule.Severity,
		Confidence:      model.ConfidenceHigh,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: mscp.ToolID, RuleID: rule.ID, RuleVersion: mscp.Version},
		},
		EvidenceIDs: []string{evidenceID, "evidence.mscp.manifest"},
		AffectedComponents: []model.AffectedComponent{
			{Kind: model.AffectedComponentConfiguration, Identifier: "mscp." + rule.ID, Name: rule.Title},
		},
		Vulnerabilities: make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         rule.Remediation,
			Steps:           []string{rule.RemediationStep},
			RequiresAdmin:   rule.RequiresAdmin,
			RequiresRestart: rule.RequiresRestart,
			References:      []string{mscp.RuleReference(rule), mscp.ReleaseURL},
		},
	}
}

func buildComplianceCoverageGap(observedAt time.Time) model.Finding {
	assessedCount := len(mscp.Rules())
	return model.Finding{
		ID:              "finding.mscp.cis-level-1-subset.coverage-gap",
		Category:        model.FindingCategoryCoverageGap,
		Title:           "mSCP CIS Level 1 coverage is intentionally limited",
		Description:     fmt.Sprintf("MacScope evaluated %d of %d rules from the pinned mSCP Tahoe Revision 3 CIS Level 1 baseline. Only rules with reviewed, fixed, read-only osquery translations are included; this report is not a full CIS compliance assessment.", assessedCount, mscp.BaselineRuleCount),
		Severity:        model.SeverityInfo,
		Confidence:      model.ConfidenceConfirmed,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: mscp.ToolID, RuleID: "macscope.osquery-subset.coverage", RuleVersion: mscp.Version},
		},
		EvidenceIDs: []string{"evidence.mscp.manifest"},
		AffectedComponents: []model.AffectedComponent{
			{Kind: model.AffectedComponentScanner, Identifier: "macscope.mscp-subset", Name: "MacScope mSCP osquery adapter"},
		},
		Vulnerabilities: make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         "Use the official mSCP-generated compliance workflow when a complete CIS Level 1 assessment is required.",
			Steps:           []string{"Review the pinned baseline and run the official mSCP compliance process in an authorized maintenance workflow with its required privileges."},
			RequiresAdmin:   true,
			RequiresRestart: false,
			References:      []string{mscp.ReleaseURL, mscp.RepositoryURL},
		},
	}
}

func buildQueryErrorFinding(identifier string, target string, observedAt time.Time, evidenceID string, queryError error) model.Finding {
	return model.Finding{
		ID:              "finding.osquery." + identifier + ".tool-error",
		Category:        model.FindingCategoryToolError,
		Title:           "osquery collection failed: " + target,
		Description:     queryError.Error(),
		Severity:        model.SeverityLow,
		Confidence:      model.ConfidenceConfirmed,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: ToolID, RuleID: "query." + identifier, RuleVersion: ExpectedVersion},
		},
		EvidenceIDs: []string{evidenceID},
		AffectedComponents: []model.AffectedComponent{
			{Kind: model.AffectedComponentScanner, Identifier: "macscope.osquery." + identifier, Name: target},
		},
		Vulnerabilities: make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         "Resolve the reported osquery execution or result-validation error, then run a new scan.",
			Steps:           []string{"Inspect the hashed osquery command artifact and execute the recorded read-only command directly to reproduce the error."},
			RequiresAdmin:   false,
			RequiresRestart: false,
			References:      []string{OriginURL},
		},
	}
}

func buildUnavailableFinding(executablePath string, verificationError error, observedAt time.Time, evidenceID string) model.Finding {
	return model.Finding{
		ID:              "finding.osquery.unavailable.tool-error",
		Category:        model.FindingCategoryToolError,
		Title:           "Pinned osquery executable is unavailable or untrusted",
		Description:     verificationError.Error() + ". MacScope did not substitute an unpinned system executable.",
		Severity:        model.SeverityLow,
		Confidence:      model.ConfidenceConfirmed,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: "macscope", RuleID: "osquery.executable-provenance", RuleVersion: "1"},
		},
		EvidenceIDs: []string{evidenceID},
		AffectedComponents: []model.AffectedComponent{
			{Kind: model.AffectedComponentScanner, Identifier: "macscope.osquery", Name: "osquery adapter", Path: executablePath},
		},
		Vulnerabilities: make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         "Install the exact project-pinned osquery release and verify its archive and executable SHA-256 values.",
			Steps:           []string{"Use tools.lock.json to install osquery into the project-local .tools directory, then run a new scan."},
			RequiresAdmin:   false,
			RequiresRestart: false,
			References:      []string{OriginURL},
		},
	}
}

func buildUnsupportedOSFinding(macOSVersion string, observedAt time.Time) model.Finding {
	return model.Finding{
		ID:              "finding.mscp.unsupported-os.coverage-gap",
		Category:        model.FindingCategoryCoverageGap,
		Title:           "Pinned mSCP guidance does not match the installed macOS major version",
		Description:     fmt.Sprintf("The pinned %s guidance is for macOS 26, while the installed version is %q. No mSCP compliance conclusion was produced.", mscp.GuidanceVersion, macOSVersion),
		Severity:        model.SeverityInfo,
		Confidence:      model.ConfidenceConfirmed,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: mscp.ToolID, RuleID: "platform-support.coverage", RuleVersion: mscp.Version},
		},
		EvidenceIDs: []string{"evidence.mscp.manifest"},
		AffectedComponents: []model.AffectedComponent{
			{Kind: model.AffectedComponentScanner, Identifier: "macscope.mscp", Name: "mSCP adapter"},
		},
		Vulnerabilities: make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         "Pin and review the mSCP guidance release matching the installed macOS major version.",
			Steps:           []string{"Update the mSCP source pin and reviewed osquery translations before enabling compliance checks for this macOS version."},
			RequiresAdmin:   false,
			RequiresRestart: false,
			References:      []string{mscp.RepositoryURL},
		},
	}
}

func manifestEvidence(observedAt time.Time, reference model.ArtifactReference) model.EvidenceRecord {
	return model.EvidenceRecord{
		ID:          "evidence.mscp.manifest",
		CollectorID: mscp.ToolID,
		Kind:        model.EvidenceKindFileMetadata,
		ObservedAt:  observedAt,
		Subject:     "pinned mSCP CIS Level 1 osquery subset manifest",
		Summary:     fmt.Sprintf("%d reviewed osquery translations from %s; full baseline contains %d rules", len(mscp.Rules()), mscp.GuidanceVersion, mscp.BaselineRuleCount),
		Command:     nil,
		Artifact:    &reference,
	}
}
