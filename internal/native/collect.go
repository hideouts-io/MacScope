package native

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"macscope/internal/artifact"
	"macscope/internal/model"
)

type Collection struct {
	HostDetails HostDetails
	Coverage    []model.CoverageRecord
	Evidence    []model.EvidenceRecord
	Findings    []model.Finding
	Artifacts   []artifact.Record
}

type CollectionError struct {
	Message string
}

func (err CollectionError) Error() string {
	return "build native collection: " + err.Message
}

type commandArtifact struct {
	SchemaVersion  string    `json:"schema_version"`
	ProbeID        string    `json:"probe_id"`
	Command        []string  `json:"command"`
	Privileged     bool      `json:"privileged"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	ExitCode       int       `json:"exit_code"`
	StandardOutput []byte    `json:"standard_output_base64"`
	StandardError  []byte    `json:"standard_error_base64"`
	ExecutionError string    `json:"execution_error,omitempty"`
}

func CollectUnprivileged(parentContext context.Context) []ProbeResult {
	return collectProbes(parentContext, unprivilegedProbeSpecs())
}

func CollectPrivileged(parentContext context.Context) []ProbeResult {
	return collectProbes(parentContext, privilegedProbeSpecs())
}

func ValidatePrivilegedResults(results []ProbeResult) error {
	return validateProbeResults(results, privilegedProbeSpecs())
}

func BuildCollection(unprivilegedResults []ProbeResult, privilegedResults []ProbeResult, privilegeRequested bool, observedAt time.Time) (Collection, error) {
	unprivilegedSpecs := unprivilegedProbeSpecs()
	if err := validateProbeResults(unprivilegedResults, unprivilegedSpecs); err != nil {
		return Collection{}, err
	}
	privilegedSpecs := privilegedProbeSpecs()
	if privilegeRequested {
		if err := validateProbeResults(privilegedResults, privilegedSpecs); err != nil {
			return Collection{}, err
		}
	} else if len(privilegedResults) != 0 {
		return Collection{}, CollectionError{Message: fmt.Sprintf("received %d privileged probe results when privilege was not requested", len(privilegedResults))}
	}

	collection := Collection{
		HostDetails: HostDetails{},
		Coverage:    make([]model.CoverageRecord, 0, len(unprivilegedSpecs)+len(privilegedSpecs)),
		Evidence:    make([]model.EvidenceRecord, 0, len(unprivilegedSpecs)+len(privilegedSpecs)),
		Findings:    make([]model.Finding, 0),
		Artifacts:   make([]artifact.Record, 0, len(unprivilegedSpecs)+len(privilegedSpecs)),
	}
	for index, spec := range unprivilegedSpecs {
		updatedCollection, err := addExecutedProbe(collection, spec, unprivilegedResults[index])
		if err != nil {
			return Collection{}, err
		}
		collection = updatedCollection
	}
	if privilegeRequested {
		for index, spec := range privilegedSpecs {
			updatedCollection, err := addExecutedProbe(collection, spec, privilegedResults[index])
			if err != nil {
				return Collection{}, err
			}
			collection = updatedCollection
		}
	} else {
		for _, spec := range privilegedSpecs {
			collection = addSkippedProbe(collection, spec, observedAt)
		}
	}
	return collection, nil
}

func collectProbes(parentContext context.Context, specs []probeSpec) []ProbeResult {
	results := make([]ProbeResult, 0, len(specs))
	for _, spec := range specs {
		results = append(results, runProbe(parentContext, spec))
	}
	return results
}

func validateProbeResults(results []ProbeResult, specs []probeSpec) error {
	if len(results) != len(specs) {
		return CollectionError{Message: fmt.Sprintf("received %d probe results; expected %d", len(results), len(specs))}
	}
	for index, result := range results {
		spec := specs[index]
		if result.ID != spec.ID {
			return CollectionError{Message: fmt.Sprintf("probe result %d has ID %q; expected %q", index, result.ID, spec.ID)}
		}
		if result.Executable != spec.Executable || !slices.Equal(result.Arguments, spec.Arguments) {
			return CollectionError{Message: fmt.Sprintf("probe result %q command does not match fixed specification", result.ID)}
		}
		if result.Privileged != spec.Privileged {
			return CollectionError{Message: fmt.Sprintf("probe result %q privileged=%t; expected %t", result.ID, result.Privileged, spec.Privileged)}
		}
		if result.StartedAt.IsZero() || result.CompletedAt.IsZero() {
			return CollectionError{Message: fmt.Sprintf("probe result %q is missing timestamps", result.ID)}
		}
		_, startedOffset := result.StartedAt.Zone()
		_, completedOffset := result.CompletedAt.Zone()
		if startedOffset != 0 || completedOffset != 0 {
			return CollectionError{Message: fmt.Sprintf("probe result %q timestamps must use UTC offset zero", result.ID)}
		}
		if result.CompletedAt.Before(result.StartedAt) {
			return CollectionError{Message: fmt.Sprintf("probe result %q completed before it started", result.ID)}
		}
		if result.ExitCode != 0 && strings.TrimSpace(result.ExecutionError) == "" {
			return CollectionError{Message: fmt.Sprintf("probe result %q has exit code %d without an execution error", result.ID, result.ExitCode)}
		}
	}
	return nil
}

func addExecutedProbe(collection Collection, spec probeSpec, result ProbeResult) (Collection, error) {
	artifact, artifactReference, err := buildArtifact(result)
	if err != nil {
		return Collection{}, err
	}
	evidenceID := "evidence.native." + spec.ID
	command := append([]string{result.Executable}, result.Arguments...)
	parsedAssessment, parseErr := spec.Parser(result)
	summary := "Native probe completed"
	coverageStatus := model.CoverageStatusComplete
	coverageReason := ""
	if parseErr != nil {
		summary = parseErr.Error()
		coverageStatus = model.CoverageStatusFailed
		coverageReason = parseErr.Error()
	} else {
		summary = parsedAssessment.Summary
	}

	updatedCollection := Collection{
		HostDetails: mergeHostDetails(collection.HostDetails, parsedAssessment.HostDetails),
		Coverage: appendCoverage(collection.Coverage, model.CoverageRecord{
			ID:                "coverage.native." + spec.ID,
			CollectorID:       "macscope",
			Area:              spec.Area,
			Target:            spec.Target,
			Status:            coverageStatus,
			Reason:            coverageReason,
			PrivilegeRequired: spec.Privileged,
			StartedAt:         result.StartedAt,
			CompletedAt:       result.CompletedAt,
		}),
		Evidence: appendEvidence(collection.Evidence, model.EvidenceRecord{
			ID:          evidenceID,
			CollectorID: "macscope",
			Kind:        model.EvidenceKindCommandOutput,
			ObservedAt:  result.CompletedAt,
			Subject:     spec.Target,
			Summary:     summary,
			Command:     command,
			Artifact:    &artifactReference,
		}),
		Findings:  copyFindings(collection.Findings),
		Artifacts: appendArtifact(collection.Artifacts, artifact),
	}
	if parseErr != nil {
		updatedCollection.Findings = appendFinding(updatedCollection.Findings, buildToolErrorFinding(spec, evidenceID, result.CompletedAt, parseErr))
		return updatedCollection, nil
	}
	if parsedAssessment.State == assessmentStateNoncompliant && spec.Rule != nil {
		updatedCollection.Findings = appendFinding(updatedCollection.Findings, buildRuleFinding(spec, evidenceID, result.CompletedAt))
	}
	return updatedCollection, nil
}

func addSkippedProbe(collection Collection, spec probeSpec, observedAt time.Time) Collection {
	evidenceID := "evidence.native." + spec.ID + ".not-scanned"
	reason := "privileged probe was not scanned because --privileged was not requested"
	return Collection{
		HostDetails: collection.HostDetails,
		Coverage: appendCoverage(collection.Coverage, model.CoverageRecord{
			ID:                "coverage.native." + spec.ID,
			CollectorID:       "macscope",
			Area:              spec.Area,
			Target:            spec.Target,
			Status:            model.CoverageStatusNotScanned,
			Reason:            reason,
			PrivilegeRequired: true,
			StartedAt:         observedAt,
			CompletedAt:       observedAt,
		}),
		Evidence: appendEvidence(collection.Evidence, model.EvidenceRecord{
			ID:          evidenceID,
			CollectorID: "macscope",
			Kind:        model.EvidenceKindObservation,
			ObservedAt:  observedAt,
			Subject:     spec.Target,
			Summary:     reason,
			Command:     nil,
			Artifact:    nil,
		}),
		Findings:  appendFinding(collection.Findings, buildCoverageGapFinding(spec, evidenceID, observedAt)),
		Artifacts: copyArtifacts(collection.Artifacts),
	}
}

func buildArtifact(result ProbeResult) (artifact.Record, model.ArtifactReference, error) {
	artifactPath := filepath.Join("evidence", "native", result.ID+".json")
	payload := commandArtifact{
		SchemaVersion:  "1",
		ProbeID:        result.ID,
		Command:        append([]string{result.Executable}, result.Arguments...),
		Privileged:     result.Privileged,
		StartedAt:      result.StartedAt,
		CompletedAt:    result.CompletedAt,
		ExitCode:       result.ExitCode,
		StandardOutput: append([]byte(nil), result.StandardOutput...),
		StandardError:  append([]byte(nil), result.StandardError...),
		ExecutionError: result.ExecutionError,
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return artifact.Record{}, model.ArtifactReference{}, CollectionError{Message: fmt.Sprintf("encode artifact for probe %q: %v", result.ID, err)}
	}
	encoded = append(encoded, '\n')
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	return artifact.Record{Path: artifactPath, Content: encoded}, model.ArtifactReference{
		Path:      artifactPath,
		SHA256:    digest,
		MediaType: "application/json",
	}, nil
}

func buildRuleFinding(spec probeSpec, evidenceID string, observedAt time.Time) model.Finding {
	rule := *spec.Rule
	return model.Finding{
		ID:              "finding.native." + spec.ID,
		Category:        rule.Category,
		Title:           rule.Title,
		Description:     rule.Description,
		Severity:        rule.Severity,
		Confidence:      model.ConfidenceConfirmed,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: "macscope", RuleID: "native." + spec.ID, RuleVersion: "1"},
		},
		EvidenceIDs: []string{evidenceID},
		AffectedComponents: []model.AffectedComponent{
			{
				Kind:       spec.Component.Kind,
				Identifier: spec.Component.Identifier,
				Name:       spec.Component.Name,
			},
		},
		Vulnerabilities: make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         rule.Remediation,
			Steps:           []string{rule.RemediationStep},
			RequiresAdmin:   rule.RequiresAdmin,
			RequiresRestart: rule.RequiresRestart,
			References:      make([]string, 0),
		},
	}
}

func buildToolErrorFinding(spec probeSpec, evidenceID string, observedAt time.Time, probeError error) model.Finding {
	return model.Finding{
		ID:              "finding.native." + spec.ID + ".tool-error",
		Category:        model.FindingCategoryToolError,
		Title:           "Native probe failed: " + spec.Target,
		Description:     probeError.Error(),
		Severity:        model.SeverityLow,
		Confidence:      model.ConfidenceConfirmed,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: "macscope", RuleID: "native." + spec.ID + ".execution", RuleVersion: "1"},
		},
		EvidenceIDs: []string{evidenceID},
		AffectedComponents: []model.AffectedComponent{
			{
				Kind:       model.AffectedComponentScanner,
				Identifier: "macscope.native." + spec.ID,
				Name:       spec.Target,
			},
		},
		Vulnerabilities: make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         "Resolve the reported command or permission failure, then run a new scan.",
			Steps:           []string{"Review the hashed command artifact and run the displayed read-only command directly in Terminal to confirm the error."},
			RequiresAdmin:   spec.Privileged,
			RequiresRestart: false,
			References:      make([]string, 0),
		},
	}
}

func buildCoverageGapFinding(spec probeSpec, evidenceID string, observedAt time.Time) model.Finding {
	return model.Finding{
		ID:              "finding.native." + spec.ID + ".coverage-gap",
		Category:        model.FindingCategoryCoverageGap,
		Title:           "Privileged coverage not requested: " + spec.Target,
		Description:     "The read-only probe was not executed because the scan did not include --privileged. This is a coverage limitation, not a failed security control.",
		Severity:        model.SeverityInfo,
		Confidence:      model.ConfidenceConfirmed,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: "macscope", RuleID: "native." + spec.ID + ".coverage", RuleVersion: "1"},
		},
		EvidenceIDs: []string{evidenceID},
		AffectedComponents: []model.AffectedComponent{
			{
				Kind:       model.AffectedComponentScanner,
				Identifier: "macscope.native." + spec.ID,
				Name:       spec.Target,
			},
		},
		Vulnerabilities: make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         "Run a new scan with explicitly authorized privileged coverage if this evidence is required.",
			Steps:           []string{"Run macscope scan --output <new-directory> --privileged and complete the sudo prompt directly in Terminal."},
			RequiresAdmin:   true,
			RequiresRestart: false,
			References:      make([]string, 0),
		},
	}
}

func mergeHostDetails(current HostDetails, additional HostDetails) HostDetails {
	return HostDetails{
		MacOSVersion:          firstNonempty(current.MacOSVersion, additional.MacOSVersion),
		MacOSBuild:            firstNonempty(current.MacOSBuild, additional.MacOSBuild),
		ModelID:               firstNonempty(current.ModelID, additional.ModelID),
		Chip:                  firstNonempty(current.Chip, additional.Chip),
		XProtectConfigVersion: firstNonempty(current.XProtectConfigVersion, additional.XProtectConfigVersion),
		XProtectVersion:       firstNonempty(current.XProtectVersion, additional.XProtectVersion),
		XProtectPluginVersion: firstNonempty(current.XProtectPluginVersion, additional.XProtectPluginVersion),
	}
}

func firstNonempty(current string, additional string) string {
	if strings.TrimSpace(additional) != "" {
		return additional
	}
	return current
}

func appendCoverage(records []model.CoverageRecord, record model.CoverageRecord) []model.CoverageRecord {
	updated := make([]model.CoverageRecord, len(records), len(records)+1)
	copy(updated, records)
	return append(updated, record)
}

func appendEvidence(records []model.EvidenceRecord, record model.EvidenceRecord) []model.EvidenceRecord {
	updated := make([]model.EvidenceRecord, len(records), len(records)+1)
	copy(updated, records)
	return append(updated, record)
}

func appendFinding(findings []model.Finding, finding model.Finding) []model.Finding {
	updated := make([]model.Finding, len(findings), len(findings)+1)
	copy(updated, findings)
	return append(updated, finding)
}

func appendArtifact(artifacts []artifact.Record, record artifact.Record) []artifact.Record {
	updated := make([]artifact.Record, len(artifacts), len(artifacts)+1)
	copy(updated, artifacts)
	return append(updated, record)
}

func copyFindings(findings []model.Finding) []model.Finding {
	copied := make([]model.Finding, len(findings))
	copy(copied, findings)
	return copied
}

func copyArtifacts(artifacts []artifact.Record) []artifact.Record {
	copied := make([]artifact.Record, len(artifacts))
	copy(copied, artifacts)
	return copied
}
