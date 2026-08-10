package osquery

import (
	"macscope/internal/artifact"
	"macscope/internal/model"
)

func copyCollection(collection Collection) Collection {
	return Collection{
		Tools:     copyTools(collection.Tools),
		Coverage:  copyCoverage(collection.Coverage),
		Evidence:  copyEvidence(collection.Evidence),
		Findings:  copyFindings(collection.Findings),
		Artifacts: copyArtifacts(collection.Artifacts),
	}
}

func appendTool(records []model.ToolRecord, record model.ToolRecord) []model.ToolRecord {
	updated := make([]model.ToolRecord, len(records), len(records)+1)
	copy(updated, records)
	return append(updated, record)
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

func appendFinding(records []model.Finding, record model.Finding) []model.Finding {
	updated := make([]model.Finding, len(records), len(records)+1)
	copy(updated, records)
	return append(updated, record)
}

func appendArtifact(records []artifact.Record, record artifact.Record) []artifact.Record {
	updated := make([]artifact.Record, len(records), len(records)+1)
	copy(updated, records)
	return append(updated, record)
}

func copyTools(records []model.ToolRecord) []model.ToolRecord {
	copied := make([]model.ToolRecord, len(records))
	copy(copied, records)
	return copied
}

func copyCoverage(records []model.CoverageRecord) []model.CoverageRecord {
	copied := make([]model.CoverageRecord, len(records))
	copy(copied, records)
	return copied
}

func copyEvidence(records []model.EvidenceRecord) []model.EvidenceRecord {
	copied := make([]model.EvidenceRecord, len(records))
	copy(copied, records)
	return copied
}

func copyFindings(records []model.Finding) []model.Finding {
	copied := make([]model.Finding, len(records))
	copy(copied, records)
	return copied
}

func copyArtifacts(records []artifact.Record) []artifact.Record {
	copied := make([]artifact.Record, len(records))
	copy(copied, records)
	return copied
}

func commandForEvidence(executablePath string, result QueryResult, kind model.EvidenceKind) []string {
	if kind != model.EvidenceKindCommandOutput {
		return nil
	}
	return append([]string{executablePath}, result.Arguments...)
}
