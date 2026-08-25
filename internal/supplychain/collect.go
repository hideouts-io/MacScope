package supplychain

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"macscope/internal/artifact"
	"macscope/internal/model"
	"macscope/internal/progress"
)

type Collection struct {
	Tools     []model.ToolRecord
	Coverage  []model.CoverageRecord
	Evidence  []model.EvidenceRecord
	Findings  []model.Finding
	Artifacts []artifact.Record
}

type commandArtifact struct {
	SchemaVersion  string               `json:"schema_version"`
	CommandID      string               `json:"command_id"`
	Command        []string             `json:"command"`
	Environment    []EnvironmentSetting `json:"environment"`
	InputSHA256    string               `json:"input_sha256,omitempty"`
	StartedAt      time.Time            `json:"started_at"`
	CompletedAt    time.Time            `json:"completed_at"`
	ExitCode       int                  `json:"exit_code"`
	StandardOutput []byte               `json:"standard_output_base64"`
	StandardError  []byte               `json:"standard_error_base64"`
	ExecutionError string               `json:"execution_error,omitempty"`
}

type outputExecutionArtifact struct {
	SchemaVersion      string               `json:"schema_version"`
	CommandID          string               `json:"command_id"`
	Command            []string             `json:"command"`
	Environment        []EnvironmentSetting `json:"environment"`
	InputSHA256        string               `json:"input_sha256,omitempty"`
	StartedAt          time.Time            `json:"started_at"`
	CompletedAt        time.Time            `json:"completed_at"`
	ExitCode           int                  `json:"exit_code"`
	StandardOutputPath string               `json:"standard_output_path"`
	StandardOutputHash string               `json:"standard_output_sha256"`
	StandardOutputSize int                  `json:"standard_output_bytes"`
	StandardError      []byte               `json:"standard_error_base64"`
	ExecutionError     string               `json:"execution_error,omitempty"`
}

type retryWarning struct {
	Level       string `json:"level"`
	Type        string `json:"type"`
	Tool        string `json:"tool"`
	Attempt     int    `json:"attempt"`
	MaxAttempts int    `json:"max_attempts"`
	Message     string `json:"message"`
}

func Collect(parentContext context.Context, client Client, macOSVersion string, excludedPaths []string, warningWriter io.Writer, observedAt time.Time, progressReporter progress.Reporter) (Collection, error) {
	if strings.TrimSpace(macOSVersion) == "" {
		return Collection{}, fmt.Errorf("collect Syft and Grype evidence: macOS version must not be empty")
	}
	collection := emptyCollection()
	if err := reportSupplyChainProgress(progressReporter, 46, "Verifying the pinned Syft executable, version, commit, and hash"); err != nil {
		return Collection{}, err
	}
	syftVerification, syftVerificationErr := client.VerifySyft(parentContext)
	if syftVerificationErr != nil {
		updated, err := addVerificationFailure(collection, SyftToolID, client.Config().SyftExecutablePath, syftVerification, syftVerificationErr, observedAt)
		if err != nil {
			return Collection{}, err
		}
		return addGrypeNotScanned(updated, observedAt, "Syft SBOM generation was unavailable: "+syftVerificationErr.Error()), nil
	}
	collection.Tools = appendTool(collection.Tools, executableToolRecord(SyftToolID, "Syft", syftVerification, SyftOriginURL, model.ToolKindCollector, client.Config().SyftExecutablePath))
	var err error
	collection, err = addSmallCommand(collection, SyftToolID, syftVerification.Result, "verified pinned Syft executable version and commit")
	if err != nil {
		return Collection{}, err
	}

	if err := reportSupplyChainProgress(progressReporter, 50, "Preparing startup-volume, home-directory, OneDrive, and local-iCloud scan scope"); err != nil {
		return Collection{}, err
	}
	syftScope, err := client.PrepareSyftScope("/Users", excludedPaths)
	if err != nil {
		return Collection{}, fmt.Errorf("prepare Syft home-directory and local-iCloud scope: %w", err)
	}
	collection = addSyftScopeEvidence(collection, syftScope, observedAt)
	if err := reportSupplyChainProgress(progressReporter, 55, "Scanning readable system and home-directory packages with Syft; large scopes can take time"); err != nil {
		return Collection{}, err
	}
	syftResult := client.RunSyft(parentContext, macOSVersion, syftScope)
	syftSummary, syftParseErr := parseSyftResult(syftResult)
	collection, err = addLargeCommandOutput(collection, SyftToolID, syftResult, "evidence/syft/filesystem.sbom.syft.json", "application/vnd.syft+json", fmt.Sprintf("Syft captured %d validated package(s) from readable startup-volume and home-directory paths; %d user-selected path(s) and %d dataless iCloud item(s) were excluded before content access", syftSummary.PackageCount, syftScope.UserExcluded, syftScope.DatalessExcluded), syftParseErr)
	if err != nil {
		return Collection{}, err
	}
	collection = addSyftCoverage(collection, syftResult, syftSummary, syftScope, syftParseErr)
	if syftParseErr != nil {
		collection.Findings = appendFinding(collection.Findings, buildToolErrorFinding(SyftToolID, "filesystem-sbom", "Syft filesystem SBOM generation failed", syftParseErr, syftResult.CompletedAt, []string{"evidence.syft.filesystem-sbom.execution", "evidence.syft.sbom"}, client.Config().SyftExecutablePath, SyftOriginURL))
		return addGrypeNotScanned(collection, syftResult.CompletedAt, "Grype requires a validated Syft SBOM: "+syftParseErr.Error()), nil
	}
	if err := client.ValidateSyftDigest(); err != nil {
		return Collection{}, err
	}

	if err := reportSupplyChainProgress(progressReporter, 72, "Syft SBOM validated; verifying the pinned Grype executable"); err != nil {
		return Collection{}, err
	}
	grypeVerification, grypeVerificationErr := client.VerifyGrype(parentContext)
	if grypeVerificationErr != nil {
		updated, addErr := addVerificationFailure(collection, GrypeToolID, client.Config().GrypeExecutablePath, grypeVerification, grypeVerificationErr, syftResult.CompletedAt)
		if addErr != nil {
			return Collection{}, addErr
		}
		return addGrypeFailedCoverage(updated, syftResult.CompletedAt, grypeVerificationErr.Error()), nil
	}
	collection.Tools = appendTool(collection.Tools, executableToolRecord(GrypeToolID, "Grype", grypeVerification, GrypeOriginURL, model.ToolKindMatcher, client.Config().GrypeExecutablePath))
	collection, err = addSmallCommand(collection, GrypeToolID, grypeVerification.Result, "verified pinned Grype executable version and commit")
	if err != nil {
		return Collection{}, err
	}

	if err := reportSupplyChainProgress(progressReporter, 76, "Updating the project-local Grype vulnerability database"); err != nil {
		return Collection{}, err
	}
	var updateErr error
	collection, updateErr = updateGrypeDatabase(parentContext, collection, client, warningWriter)
	if updateErr != nil {
		collection = addGrypeFailedCoverage(collection, time.Now().UTC(), updateErr.Error())
		collection.Findings = appendFinding(collection.Findings, buildToolErrorFinding(GrypeToolID, "database-update", "Grype vulnerability database update failed", updateErr, time.Now().UTC(), databaseUpdateEvidenceIDs(client.Config().DatabaseUpdateAttempts), client.Config().GrypeDatabaseDirectory, GrypeOriginURL))
		return collection, nil
	}

	if err := reportSupplyChainProgress(progressReporter, 81, "Validating Grype database schema, age, source, and digest"); err != nil {
		return Collection{}, err
	}
	statusResult := client.RunGrypeDatabaseStatus(parentContext)
	database, statusErr := parseDatabaseStatusResult(statusResult, client.Config().GrypeDatabaseDirectory)
	collection, err = addSmallCommand(collection, GrypeToolID, statusResult, databaseStatusSummary(database, statusErr))
	if err != nil {
		return Collection{}, err
	}
	if statusErr != nil {
		collection = addGrypeFailedCoverage(collection, statusResult.CompletedAt, statusErr.Error())
		collection.Findings = appendFinding(collection.Findings, buildToolErrorFinding(GrypeToolID, "db-status", "Grype vulnerability database validation failed", statusErr, statusResult.CompletedAt, []string{"evidence.grype.db-status"}, client.Config().GrypeDatabaseDirectory, GrypeOriginURL))
		return collection, nil
	}
	collection.Tools = addDatabaseIdentity(collection.Tools, database)

	if err := reportSupplyChainProgress(progressReporter, 85, "Matching the validated Syft SBOM against the Grype database"); err != nil {
		return Collection{}, err
	}
	grypeResult := client.RunGrype(parentContext, syftResult.StandardOutput)
	grypeDocument, grypeParseErr := parseGrypeResult(grypeResult, database)
	collection, err = addLargeCommandOutput(collection, GrypeToolID, grypeResult, "evidence/grype/vulnerability-report.json", "application/vnd.anchore.grype+json", fmt.Sprintf("Grype produced %d unique validated vulnerability match(es) from %d raw match record(s) for %d Syft package(s)", len(grypeDocument.Matches), grypeDocument.RawMatchCount, syftSummary.PackageCount), grypeParseErr)
	if err != nil {
		return Collection{}, err
	}
	if grypeParseErr != nil {
		collection = addGrypeFailedCoverage(collection, grypeResult.CompletedAt, grypeParseErr.Error())
		collection.Findings = appendFinding(collection.Findings, buildToolErrorFinding(GrypeToolID, "vulnerability-match", "Grype vulnerability matching failed", grypeParseErr, grypeResult.CompletedAt, []string{"evidence.grype.vulnerability-match.execution", "evidence.grype.report", "evidence.grype.db-status", "evidence.syft.sbom"}, client.Config().GrypeExecutablePath, GrypeOriginURL))
		return collection, nil
	}
	if err := validateDatabaseDigest(database); err != nil {
		return Collection{}, err
	}
	if err := client.ValidateGrypeDigest(); err != nil {
		return Collection{}, err
	}
	collection.Coverage = appendCoverage(collection.Coverage, model.CoverageRecord{
		ID:                "coverage.grype.dependencies",
		CollectorID:       GrypeToolID,
		Area:              model.CoverageAreaDependencyVulnerabilities,
		Target:            "Grype matching of packages captured in the Syft root-filesystem SBOM",
		Status:            model.CoverageStatusComplete,
		Reason:            "",
		PrivilegeRequired: false,
		StartedAt:         grypeResult.StartedAt,
		CompletedAt:       grypeResult.CompletedAt,
	})
	findings, findingsErr := buildVulnerabilityFindings(grypeDocument, database, grypeResult.CompletedAt)
	if findingsErr != nil {
		return Collection{}, findingsErr
	}
	collection.Findings = appendFindings(collection.Findings, findings)
	return collection, nil
}

func reportSupplyChainProgress(reporter progress.Reporter, percent int, message string) error {
	if err := reporter(progress.Event{Percent: percent, Message: message}); err != nil {
		return fmt.Errorf("report supply-chain progress at %d percent: %w", percent, err)
	}
	return nil
}

func emptyCollection() Collection {
	return Collection{
		Tools:     make([]model.ToolRecord, 0),
		Coverage:  make([]model.CoverageRecord, 0),
		Evidence:  make([]model.EvidenceRecord, 0),
		Findings:  make([]model.Finding, 0),
		Artifacts: make([]artifact.Record, 0),
	}
}

func parseSyftResult(result CommandResult) (SyftSummary, error) {
	if err := successfulCommand(result); err != nil {
		return SyftSummary{}, err
	}
	return parseSyftDocument(result.StandardOutput)
}

func parseDatabaseStatusResult(result CommandResult, databaseDirectory string) (DatabaseIdentity, error) {
	if err := successfulCommand(result); err != nil {
		return DatabaseIdentity{}, err
	}
	return parseDatabaseStatus(result.StandardOutput, databaseDirectory)
}

func parseGrypeResult(result CommandResult, database DatabaseIdentity) (GrypeDocument, error) {
	if err := successfulCommand(result); err != nil {
		return GrypeDocument{}, err
	}
	return parseGrypeDocument(result.StandardOutput, database)
}

func updateGrypeDatabase(parentContext context.Context, collection Collection, client Client, warningWriter io.Writer) (Collection, error) {
	updated := copyCollection(collection)
	config := client.Config()
	var lastErr error
	for attempt := 1; attempt <= config.DatabaseUpdateAttempts; attempt++ {
		result := client.RunGrypeDatabaseUpdate(parentContext, attempt)
		var artifactErr error
		updated, artifactErr = addSmallCommand(updated, GrypeToolID, result, fmt.Sprintf("Grype vulnerability database update attempt %d of %d", attempt, config.DatabaseUpdateAttempts))
		if artifactErr != nil {
			return Collection{}, artifactErr
		}
		lastErr = successfulDatabaseUpdate(result)
		if lastErr == nil {
			return updated, nil
		}
		if attempt == config.DatabaseUpdateAttempts {
			break
		}
		if err := writeRetryWarning(warningWriter, retryWarning{
			Level:       "warning",
			Type:        "database_update_retry",
			Tool:        GrypeToolID,
			Attempt:     attempt,
			MaxAttempts: config.DatabaseUpdateAttempts,
			Message:     lastErr.Error(),
		}); err != nil {
			return Collection{}, err
		}
		select {
		case <-parentContext.Done():
			return updated, fmt.Errorf("Grype database update retry canceled: %w", parentContext.Err())
		case <-time.After(config.DatabaseRetryDelays[attempt-1]):
		}
	}
	return updated, fmt.Errorf("update Grype vulnerability database after %d attempt(s): %w", config.DatabaseUpdateAttempts, lastErr)
}

func successfulDatabaseUpdate(result CommandResult) error {
	if result.ExecutionError != "" || result.ExitCode != 0 {
		return fmt.Errorf("command %s failed: exit_code=%d execution_error=%q stdout=%q stderr=%q", result.ID, result.ExitCode, result.ExecutionError, string(result.StandardOutput), string(result.StandardError))
	}
	return nil
}

func writeRetryWarning(writer io.Writer, warning retryWarning) error {
	if writer == nil {
		return fmt.Errorf("write Grype database retry warning: warning writer must not be nil")
	}
	encoded, err := json.Marshal(warning)
	if err != nil {
		return fmt.Errorf("encode Grype database retry warning: %w", err)
	}
	encoded = append(encoded, '\n')
	if _, err := writer.Write(encoded); err != nil {
		return fmt.Errorf("write Grype database retry warning: %w", err)
	}
	return nil
}

func addSyftCoverage(collection Collection, result CommandResult, summary SyftSummary, scope SyftScope, parseErr error) Collection {
	status := model.CoverageStatusPartial
	reason := fmt.Sprintf("captured %d package(s) from readable startup-volume and home-directory paths using Syft schema %s; %d user-selected path(s), OneDrive, user caches, %d iCloud item(s) marked dataless before scanning, protected unreadable paths, external and duplicate system volumes, migration templates, model assets, project runtime output, and volatile data were not assessed", summary.PackageCount, summary.SchemaVersion, scope.UserExcluded, scope.DatalessExcluded)
	if parseErr != nil {
		status = model.CoverageStatusFailed
		reason = parseErr.Error()
	}
	updated := copyCollection(collection)
	updated.Coverage = appendCoverage(updated.Coverage, model.CoverageRecord{
		ID:                "coverage.syft.installed-software",
		CollectorID:       SyftToolID,
		Area:              model.CoverageAreaInstalledSoftware,
		Target:            "readable package metadata on the macOS startup volume",
		Status:            status,
		Reason:            reason,
		PrivilegeRequired: false,
		StartedAt:         result.StartedAt,
		CompletedAt:       result.CompletedAt,
	})
	return updated
}

func addSyftScopeEvidence(collection Collection, scope SyftScope, observedAt time.Time) Collection {
	record, reference := buildRawArtifact("evidence/syft/scan-scope.yaml", "application/yaml", scope.ConfigContent)
	updated := copyCollection(collection)
	updated.Artifacts = appendArtifact(updated.Artifacts, record)
	updated.Evidence = appendEvidence(updated.Evidence, model.EvidenceRecord{
		ID:          "evidence.syft.scan-scope",
		CollectorID: SyftToolID,
		Kind:        model.EvidenceKindFileMetadata,
		ObservedAt:  observedAt,
		Subject:     "Syft fixed and runtime filesystem exclusions",
		Summary:     fmt.Sprintf("preserved the exact Syft configuration; %d user-selected path(s) and %d dataless iCloud item(s) were excluded before Syft could read their content", scope.UserExcluded, scope.DatalessExcluded),
		Command:     nil,
		Artifact:    &reference,
	})
	return updated
}

func addGrypeNotScanned(collection Collection, observedAt time.Time, reason string) Collection {
	updated := copyCollection(collection)
	evidenceID := updated.Evidence[len(updated.Evidence)-1].ID
	updated.Coverage = appendCoverage(updated.Coverage, model.CoverageRecord{
		ID:                "coverage.grype.not-scanned",
		CollectorID:       "macscope",
		Area:              model.CoverageAreaDependencyVulnerabilities,
		Target:            "Grype matching of captured Syft packages",
		Status:            model.CoverageStatusNotScanned,
		Reason:            reason,
		PrivilegeRequired: false,
		StartedAt:         observedAt,
		CompletedAt:       observedAt,
	})
	updated.Findings = appendFinding(updated.Findings, buildCoverageGapFinding("grype-not-scanned", "Grype vulnerability matching was not performed", reason, observedAt, evidenceID))
	return updated
}

func addGrypeFailedCoverage(collection Collection, observedAt time.Time, reason string) Collection {
	updated := copyCollection(collection)
	updated.Coverage = appendCoverage(updated.Coverage, model.CoverageRecord{
		ID:                "coverage.grype.failure",
		CollectorID:       toolCollectorID(updated.Tools, GrypeToolID),
		Area:              model.CoverageAreaDependencyVulnerabilities,
		Target:            "Grype matching of captured Syft packages",
		Status:            model.CoverageStatusFailed,
		Reason:            reason,
		PrivilegeRequired: false,
		StartedAt:         observedAt,
		CompletedAt:       observedAt,
	})
	return updated
}

func databaseStatusSummary(database DatabaseIdentity, statusErr error) string {
	if statusErr != nil {
		return statusErr.Error()
	}
	return fmt.Sprintf("Grype database %s built %s is valid with SHA-256 %s", database.SchemaVersion, database.BuiltAt.Format(time.RFC3339Nano), database.SHA256)
}

func validateDatabaseDigest(database DatabaseIdentity) error {
	digest, err := hashFile(database.Path)
	if err != nil {
		return fmt.Errorf("rehash Grype vulnerability database after matching: %w", err)
	}
	if digest != database.SHA256 {
		return fmt.Errorf("Grype vulnerability database SHA-256 changed during matching: expected %s, calculated %s", database.SHA256, digest)
	}
	return nil
}

func executableToolRecord(identifier string, name string, verification ExecutableVerification, origin string, kind model.ToolKind, path string) model.ToolRecord {
	return model.ToolRecord{
		ID:      identifier,
		Name:    name,
		Version: verification.Version,
		Kind:    kind,
		Origin:  origin,
		Executable: &model.ExecutableIdentity{
			Path:   path,
			SHA256: verification.SHA256,
		},
	}
}

func addDatabaseIdentity(tools []model.ToolRecord, database DatabaseIdentity) []model.ToolRecord {
	updated := copyTools(tools)
	for index, tool := range updated {
		if tool.ID != GrypeToolID {
			continue
		}
		updated[index].Data = &model.DataIdentity{
			Version:   database.SchemaVersion,
			UpdatedAt: database.BuiltAt,
			SHA256:    database.SHA256,
		}
		return updated
	}
	return updated
}

func addVerificationFailure(collection Collection, toolID string, executablePath string, verification ExecutableVerification, verificationErr error, observedAt time.Time) (Collection, error) {
	updated := copyCollection(collection)
	evidenceID := "evidence." + toolID + ".unavailable"
	if !verification.Result.StartedAt.IsZero() {
		var err error
		updated, err = addSmallCommandWithCollector(updated, "macscope", toolID, verification.Result, verificationErr.Error())
		if err != nil {
			return Collection{}, err
		}
		evidenceID = "evidence." + toolID + "." + verification.Result.ID
	} else {
		updated.Evidence = appendEvidence(updated.Evidence, model.EvidenceRecord{
			ID:          evidenceID,
			CollectorID: "macscope",
			Kind:        model.EvidenceKindObservation,
			ObservedAt:  observedAt,
			Subject:     "pinned " + toolID + " executable",
			Summary:     verificationErr.Error(),
			Command:     nil,
			Artifact:    nil,
		})
	}
	if toolID == SyftToolID {
		updated.Coverage = appendCoverage(updated.Coverage, model.CoverageRecord{
			ID:                "coverage.syft.unavailable",
			CollectorID:       "macscope",
			Area:              model.CoverageAreaInstalledSoftware,
			Target:            "readable package metadata on the macOS startup volume",
			Status:            model.CoverageStatusFailed,
			Reason:            verificationErr.Error(),
			PrivilegeRequired: false,
			StartedAt:         observedAt,
			CompletedAt:       observedAt,
		})
	}
	updated.Findings = appendFinding(updated.Findings, buildToolErrorFinding(toolID, "executable-provenance", "Pinned "+toolID+" executable is unavailable or untrusted", verificationErr, observedAt, []string{evidenceID}, executablePath, toolOrigin(toolID)))
	return updated, nil
}

func toolOrigin(toolID string) string {
	if toolID == SyftToolID {
		return SyftOriginURL
	}
	return GrypeOriginURL
}

func toolCollectorID(tools []model.ToolRecord, requested string) string {
	for _, tool := range tools {
		if tool.ID == requested {
			return requested
		}
	}
	return "macscope"
}

func databaseUpdateEvidenceIDs(attempts int) []string {
	identifiers := make([]string, 0, attempts)
	for attempt := 1; attempt <= attempts; attempt++ {
		identifiers = append(identifiers, fmt.Sprintf("evidence.grype.db-update-attempt-%d", attempt))
	}
	return identifiers
}

func addSmallCommand(collection Collection, collectorID string, result CommandResult, summary string) (Collection, error) {
	return addSmallCommandWithCollector(collection, collectorID, collectorID, result, summary)
}

func addSmallCommandWithCollector(collection Collection, collectorID string, artifactDirectory string, result CommandResult, summary string) (Collection, error) {
	record, reference, err := buildCommandArtifact(artifactDirectory, result)
	if err != nil {
		return Collection{}, err
	}
	updated := copyCollection(collection)
	updated.Artifacts = appendArtifact(updated.Artifacts, record)
	updated.Evidence = appendEvidence(updated.Evidence, model.EvidenceRecord{
		ID:          "evidence." + artifactDirectory + "." + result.ID,
		CollectorID: collectorID,
		Kind:        model.EvidenceKindCommandOutput,
		ObservedAt:  result.CompletedAt,
		Subject:     artifactDirectory + " " + result.ID,
		Summary:     summary,
		Command:     append([]string{result.ExecutablePath}, result.Arguments...),
		Artifact:    &reference,
	})
	return updated, nil
}

func addLargeCommandOutput(collection Collection, collectorID string, result CommandResult, outputPath string, mediaType string, summary string, commandErr error) (Collection, error) {
	outputRecord, outputReference := buildRawArtifact(outputPath, mediaType, result.StandardOutput)
	executionRecord, executionReference, err := buildOutputExecutionArtifact(collectorID, result, outputReference)
	if err != nil {
		return Collection{}, err
	}
	if commandErr != nil {
		summary = commandErr.Error()
	}
	updated := copyCollection(collection)
	updated.Artifacts = appendArtifact(updated.Artifacts, outputRecord)
	updated.Artifacts = appendArtifact(updated.Artifacts, executionRecord)
	updated.Evidence = appendEvidence(updated.Evidence, model.EvidenceRecord{
		ID:          "evidence." + collectorID + "." + result.ID + ".execution",
		CollectorID: collectorID,
		Kind:        model.EvidenceKindCommandOutput,
		ObservedAt:  result.CompletedAt,
		Subject:     collectorID + " " + result.ID + " execution",
		Summary:     summary,
		Command:     append([]string{result.ExecutablePath}, result.Arguments...),
		Artifact:    &executionReference,
	})
	outputEvidenceID := "evidence." + collectorID + ".report"
	if collectorID == SyftToolID {
		outputEvidenceID = "evidence.syft.sbom"
	}
	updated.Evidence = appendEvidence(updated.Evidence, model.EvidenceRecord{
		ID:          outputEvidenceID,
		CollectorID: collectorID,
		Kind:        model.EvidenceKindFileMetadata,
		ObservedAt:  result.CompletedAt,
		Subject:     collectorID + " structured output",
		Summary:     summary,
		Command:     nil,
		Artifact:    &outputReference,
	})
	return updated, nil
}

func buildCommandArtifact(directory string, result CommandResult) (artifact.Record, model.ArtifactReference, error) {
	artifactPath := filepath.Join("evidence", directory, result.ID+".json")
	payload := commandArtifact{
		SchemaVersion:  "1",
		CommandID:      result.ID,
		Command:        append([]string{result.ExecutablePath}, result.Arguments...),
		Environment:    append([]EnvironmentSetting(nil), result.Environment...),
		InputSHA256:    result.InputSHA256,
		StartedAt:      result.StartedAt,
		CompletedAt:    result.CompletedAt,
		ExitCode:       result.ExitCode,
		StandardOutput: append([]byte(nil), result.StandardOutput...),
		StandardError:  append([]byte(nil), result.StandardError...),
		ExecutionError: result.ExecutionError,
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return artifact.Record{}, model.ArtifactReference{}, fmt.Errorf("encode %s command artifact %q: %w", directory, result.ID, err)
	}
	encoded = append(encoded, '\n')
	reference := artifactReference(artifactPath, "application/json", encoded)
	return artifact.Record{Path: artifactPath, Content: encoded}, reference, nil
}

func buildOutputExecutionArtifact(directory string, result CommandResult, outputReference model.ArtifactReference) (artifact.Record, model.ArtifactReference, error) {
	artifactPath := filepath.Join("evidence", directory, result.ID+".execution.json")
	payload := outputExecutionArtifact{
		SchemaVersion:      "1",
		CommandID:          result.ID,
		Command:            append([]string{result.ExecutablePath}, result.Arguments...),
		Environment:        append([]EnvironmentSetting(nil), result.Environment...),
		InputSHA256:        result.InputSHA256,
		StartedAt:          result.StartedAt,
		CompletedAt:        result.CompletedAt,
		ExitCode:           result.ExitCode,
		StandardOutputPath: outputReference.Path,
		StandardOutputHash: outputReference.SHA256,
		StandardOutputSize: len(result.StandardOutput),
		StandardError:      append([]byte(nil), result.StandardError...),
		ExecutionError:     result.ExecutionError,
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return artifact.Record{}, model.ArtifactReference{}, fmt.Errorf("encode %s output execution artifact %q: %w", directory, result.ID, err)
	}
	encoded = append(encoded, '\n')
	reference := artifactReference(artifactPath, "application/json", encoded)
	return artifact.Record{Path: artifactPath, Content: encoded}, reference, nil
}

func buildRawArtifact(path string, mediaType string, content []byte) (artifact.Record, model.ArtifactReference) {
	copied := append([]byte(nil), content...)
	return artifact.Record{Path: path, Content: copied}, artifactReference(path, mediaType, copied)
}

func artifactReference(path string, mediaType string, content []byte) model.ArtifactReference {
	return model.ArtifactReference{
		Path:      path,
		SHA256:    fmt.Sprintf("%x", sha256.Sum256(content)),
		MediaType: mediaType,
	}
}

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

func appendFindings(records []model.Finding, additions []model.Finding) []model.Finding {
	updated := make([]model.Finding, 0, len(records)+len(additions))
	updated = append(updated, records...)
	return append(updated, additions...)
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
