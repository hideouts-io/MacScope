package osquery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"macscope/internal/artifact"
	"macscope/internal/model"
	"macscope/internal/mscp"
)

type Collection struct {
	Tools     []model.ToolRecord
	Coverage  []model.CoverageRecord
	Evidence  []model.EvidenceRecord
	Findings  []model.Finding
	Artifacts []artifact.Record
}

type commandArtifact struct {
	SchemaVersion  string    `json:"schema_version"`
	QueryID        string    `json:"query_id"`
	Command        []string  `json:"command"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	ExitCode       int       `json:"exit_code"`
	StandardOutput []byte    `json:"standard_output_base64"`
	StandardError  []byte    `json:"standard_error_base64"`
	ExecutionError string    `json:"execution_error,omitempty"`
}

type querySpec struct {
	ID     string
	Area   model.CoverageArea
	Target string
	SQL    string
	Parser func(QueryResult) (int, error)
}

type applicationRow struct {
	Name               string `json:"name"`
	Path               string `json:"path"`
	BundleIdentifier   string `json:"bundle_identifier"`
	BundleShortVersion string `json:"bundle_short_version"`
	BundleVersion      string `json:"bundle_version"`
}

type startupItemRow struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Type     string `json:"type"`
	Source   string `json:"source"`
	Status   string `json:"status"`
	Username string `json:"username"`
}

type launchdRow struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Label     string `json:"label"`
	Program   string `json:"program"`
	RunAtLoad string `json:"run_at_load"`
	KeepAlive string `json:"keep_alive"`
	Disabled  string `json:"disabled"`
	Username  string `json:"username"`
	GroupName string `json:"groupname"`
}

type listeningPortRow struct {
	PID      string `json:"pid"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Address  string `json:"address"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	Family   string `json:"family"`
}

type complianceValueRow struct {
	Value string `json:"value"`
}

func Collect(parentContext context.Context, client Client, macOSVersion string, observedAt time.Time) (Collection, error) {
	manifestArtifact, manifestReference, manifestErr := mscp.ManifestArtifact()
	if manifestErr != nil {
		return Collection{}, manifestErr
	}
	collection := Collection{
		Tools:     []model.ToolRecord{mscp.ToolRecord()},
		Coverage:  make([]model.CoverageRecord, 0),
		Evidence:  []model.EvidenceRecord{manifestEvidence(observedAt, manifestReference)},
		Findings:  make([]model.Finding, 0),
		Artifacts: []artifact.Record{manifestArtifact},
	}
	verification, verificationErr := client.Verify(parentContext)
	if verificationErr != nil {
		return addUnavailableCoverage(collection, client.ExecutablePath(), verification, verificationErr, time.Now().UTC())
	}
	collection.Tools = appendTool(collection.Tools, model.ToolRecord{
		ID:      ToolID,
		Name:    "osquery",
		Version: verification.Version,
		Kind:    model.ToolKindCollector,
		Origin:  OriginURL,
		Executable: &model.ExecutableIdentity{
			Path:   client.ExecutablePath(),
			SHA256: verification.SHA256,
		},
	})
	collection, manifestErr = addExecutedQuery(collection, client, verification.Result, "osquery executable version", nil)
	if manifestErr != nil {
		return Collection{}, manifestErr
	}

	for _, spec := range inventoryQuerySpecs() {
		result := client.Query(parentContext, spec.ID, spec.SQL)
		rowCount, parseErr := spec.Parser(result)
		collection, manifestErr = addInventoryQuery(collection, client, spec, result, rowCount, parseErr)
		if manifestErr != nil {
			return Collection{}, manifestErr
		}
	}

	if !mscp.SupportsMacOS(macOSVersion) {
		unsupportedCollection := addUnsupportedCompliance(collection, macOSVersion, observedAt)
		if err := client.ValidatePinnedDigest(); err != nil {
			return Collection{}, err
		}
		return unsupportedCollection, nil
	}
	complianceCollection, complianceErr := addComplianceQueries(collection, parentContext, client, observedAt)
	if complianceErr != nil {
		return Collection{}, complianceErr
	}
	if err := client.ValidatePinnedDigest(); err != nil {
		return Collection{}, err
	}
	return complianceCollection, nil
}

func inventoryQuerySpecs() []querySpec {
	return []querySpec{
		{
			ID:     "apps",
			Area:   model.CoverageAreaInstalledSoftware,
			Target: "installed macOS application inventory",
			SQL:    "SELECT name, path, bundle_identifier, bundle_short_version, bundle_version FROM apps ORDER BY path;",
			Parser: parseApplications,
		},
		{
			ID:     "startup-items",
			Area:   model.CoverageAreaPersistence,
			Target: "background startup item inventory",
			SQL:    "SELECT name, path, type, source, status, username FROM startup_items ORDER BY path, name;",
			Parser: parseStartupItems,
		},
		{
			ID:     "launchd",
			Area:   model.CoverageAreaPersistence,
			Target: "launchd definition inventory",
			SQL:    "SELECT path, name, label, program, run_at_load, keep_alive, disabled, username, groupname FROM launchd ORDER BY path;",
			Parser: parseLaunchd,
		},
		{
			ID:     "listening-ports",
			Area:   model.CoverageAreaNetworkExposure,
			Target: "local listening socket inventory",
			SQL:    "SELECT CAST(lp.pid AS TEXT) AS pid, p.name, p.path, lp.address, CAST(lp.port AS TEXT) AS port, CAST(lp.protocol AS TEXT) AS protocol, CAST(lp.family AS TEXT) AS family FROM listening_ports AS lp LEFT JOIN processes AS p ON lp.pid = p.pid WHERE lp.port != 0 ORDER BY lp.protocol, lp.address, lp.port, lp.pid;",
			Parser: parseListeningPorts,
		},
	}
}

func addInventoryQuery(collection Collection, client Client, spec querySpec, result QueryResult, rowCount int, parseErr error) (Collection, error) {
	coverageStatus := model.CoverageStatusComplete
	coverageReason := ""
	if parseErr != nil {
		coverageStatus = model.CoverageStatusFailed
		coverageReason = parseErr.Error()
	}
	updated, artifactErr := addExecutedQuery(collection, client, result, fmt.Sprintf("osquery returned %d validated row(s) for %s", rowCount, spec.Target), parseErr)
	if artifactErr != nil {
		return Collection{}, artifactErr
	}
	updated.Coverage = appendCoverage(updated.Coverage, model.CoverageRecord{
		ID:                "coverage.osquery." + spec.ID,
		CollectorID:       ToolID,
		Area:              spec.Area,
		Target:            spec.Target,
		Status:            coverageStatus,
		Reason:            coverageReason,
		PrivilegeRequired: false,
		StartedAt:         result.StartedAt,
		CompletedAt:       result.CompletedAt,
	})
	if parseErr != nil {
		updated.Findings = appendFinding(updated.Findings, buildQueryErrorFinding(spec.ID, spec.Target, result.CompletedAt, "evidence.osquery."+spec.ID, parseErr))
	}
	return updated, nil
}

func addComplianceQueries(collection Collection, parentContext context.Context, client Client, observedAt time.Time) (Collection, error) {
	rules := mscp.Rules()
	startedAt := observedAt
	completedAt := observedAt
	failureMessages := make([]string, 0)
	updated := copyCollection(collection)
	for index, rule := range rules {
		result := client.Query(parentContext, "mscp-"+rule.ID, rule.SQL)
		if index == 0 {
			startedAt = result.StartedAt
		}
		completedAt = result.CompletedAt
		value, parseErr := parseComplianceValue(result)
		summary := fmt.Sprintf("mSCP rule %s observed value %q", rule.ID, value)
		if parseErr != nil {
			summary = parseErr.Error()
			failureMessages = append(failureMessages, fmt.Sprintf("%s: %v", rule.ID, parseErr))
		}
		var artifactErr error
		updated, artifactErr = addExecutedQuery(updated, client, result, summary, parseErr)
		if artifactErr != nil {
			return Collection{}, artifactErr
		}
		evidenceID := "evidence.osquery.mscp-" + rule.ID
		if parseErr != nil {
			updated.Findings = appendFinding(updated.Findings, buildQueryErrorFinding("mscp-"+rule.ID, rule.Title, result.CompletedAt, evidenceID, parseErr))
			continue
		}
		if !mscp.IsExpected(rule, value) {
			updated.Findings = appendFinding(updated.Findings, buildComplianceFinding(rule, value, result.CompletedAt, evidenceID))
		}
	}
	coverageStatus := model.CoverageStatusPartial
	coverageReason := fmt.Sprintf("evaluated %d of %d mSCP Tahoe Revision 3 CIS Level 1 rules through fixed read-only osquery SQL; remaining rules were not assessed", len(rules), mscp.BaselineRuleCount)
	if len(failureMessages) > 0 {
		coverageStatus = model.CoverageStatusFailed
		coverageReason = coverageReason + "; query failures: " + strings.Join(failureMessages, "; ")
	}
	updated.Coverage = appendCoverage(updated.Coverage, model.CoverageRecord{
		ID:                "coverage.mscp.cis-level-1-subset",
		CollectorID:       mscp.ToolID,
		Area:              model.CoverageAreaSecurityControls,
		Target:            "mSCP Tahoe Revision 3 CIS Level 1 baseline",
		Status:            coverageStatus,
		Reason:            coverageReason,
		PrivilegeRequired: false,
		StartedAt:         startedAt,
		CompletedAt:       completedAt,
	})
	updated.Findings = appendFinding(updated.Findings, buildComplianceCoverageGap(observedAt))
	return updated, nil
}

func addUnsupportedCompliance(collection Collection, macOSVersion string, observedAt time.Time) Collection {
	reason := fmt.Sprintf("pinned mSCP guidance %s supports macOS 26, not installed macOS version %q", mscp.Version, macOSVersion)
	updated := copyCollection(collection)
	updated.Coverage = appendCoverage(updated.Coverage, model.CoverageRecord{
		ID:                "coverage.mscp.unsupported-os",
		CollectorID:       mscp.ToolID,
		Area:              model.CoverageAreaSecurityControls,
		Target:            "mSCP CIS Level 1 baseline",
		Status:            model.CoverageStatusNotScanned,
		Reason:            reason,
		PrivilegeRequired: false,
		StartedAt:         observedAt,
		CompletedAt:       observedAt,
	})
	updated.Findings = appendFinding(updated.Findings, buildUnsupportedOSFinding(macOSVersion, observedAt))
	return updated
}

func addUnavailableCoverage(collection Collection, executablePath string, verification Verification, verificationErr error, observedAt time.Time) (Collection, error) {
	updated := copyCollection(collection)
	evidenceID := "evidence.osquery.unavailable"
	evidenceKind := model.EvidenceKindObservation
	var artifactReference *model.ArtifactReference
	if !verification.Result.StartedAt.IsZero() {
		record, reference, artifactErr := buildCommandArtifact(executablePath, verification.Result)
		if artifactErr != nil {
			return Collection{}, artifactErr
		}
		updated.Artifacts = appendArtifact(updated.Artifacts, record)
		artifactReference = &reference
		evidenceKind = model.EvidenceKindCommandOutput
	}
	updated.Evidence = appendEvidence(updated.Evidence, model.EvidenceRecord{
		ID:          evidenceID,
		CollectorID: "macscope",
		Kind:        evidenceKind,
		ObservedAt:  verificationObservedAt(verification.Result, observedAt),
		Subject:     "pinned osquery executable",
		Summary:     verificationErr.Error(),
		Command:     commandForEvidence(executablePath, verification.Result, evidenceKind),
		Artifact:    artifactReference,
	})
	targets := []struct {
		ID   string
		Area model.CoverageArea
		Name string
	}{
		{ID: "apps", Area: model.CoverageAreaInstalledSoftware, Name: "installed macOS application inventory"},
		{ID: "persistence", Area: model.CoverageAreaPersistence, Name: "startup and launchd inventory"},
		{ID: "listening-ports", Area: model.CoverageAreaNetworkExposure, Name: "local listening socket inventory"},
	}
	for _, target := range targets {
		updated.Coverage = appendCoverage(updated.Coverage, model.CoverageRecord{
			ID:                "coverage.osquery." + target.ID + ".unavailable",
			CollectorID:       "macscope",
			Area:              target.Area,
			Target:            target.Name,
			Status:            model.CoverageStatusFailed,
			Reason:            verificationErr.Error(),
			PrivilegeRequired: false,
			StartedAt:         observedAt,
			CompletedAt:       observedAt,
		})
	}
	updated.Coverage = appendCoverage(updated.Coverage, model.CoverageRecord{
		ID:                "coverage.mscp.osquery-unavailable",
		CollectorID:       mscp.ToolID,
		Area:              model.CoverageAreaSecurityControls,
		Target:            "mSCP osquery-translatable CIS Level 1 subset",
		Status:            model.CoverageStatusFailed,
		Reason:            verificationErr.Error(),
		PrivilegeRequired: false,
		StartedAt:         observedAt,
		CompletedAt:       observedAt,
	})
	updated.Findings = appendFinding(updated.Findings, buildUnavailableFinding(executablePath, verificationErr, observedAt, evidenceID))
	return updated, nil
}

func verificationObservedAt(result QueryResult, fallback time.Time) time.Time {
	if !result.CompletedAt.IsZero() {
		return result.CompletedAt
	}
	return fallback
}

func addExecutedQuery(collection Collection, client Client, result QueryResult, summary string, queryError error) (Collection, error) {
	record, reference, artifactErr := buildCommandArtifact(client.ExecutablePath(), result)
	if artifactErr != nil {
		return Collection{}, artifactErr
	}
	if queryError != nil {
		summary = queryError.Error()
	}
	return Collection{
		Tools:    copyTools(collection.Tools),
		Coverage: copyCoverage(collection.Coverage),
		Evidence: appendEvidence(collection.Evidence, model.EvidenceRecord{
			ID:          "evidence.osquery." + result.ID,
			CollectorID: ToolID,
			Kind:        model.EvidenceKindCommandOutput,
			ObservedAt:  result.CompletedAt,
			Subject:     "osquery " + result.ID,
			Summary:     summary,
			Command:     append([]string{client.ExecutablePath()}, result.Arguments...),
			Artifact:    &reference,
		}),
		Findings:  copyFindings(collection.Findings),
		Artifacts: appendArtifact(collection.Artifacts, record),
	}, nil
}

func buildCommandArtifact(executablePath string, result QueryResult) (artifact.Record, model.ArtifactReference, error) {
	artifactPath := filepath.Join("evidence", "osquery", result.ID+".json")
	payload := commandArtifact{
		SchemaVersion:  "1",
		QueryID:        result.ID,
		Command:        append([]string{executablePath}, result.Arguments...),
		StartedAt:      result.StartedAt,
		CompletedAt:    result.CompletedAt,
		ExitCode:       result.ExitCode,
		StandardOutput: append([]byte(nil), result.StandardOutput...),
		StandardError:  append([]byte(nil), result.StandardError...),
		ExecutionError: result.ExecutionError,
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return artifact.Record{}, model.ArtifactReference{}, fmt.Errorf("encode osquery artifact %q: %w", result.ID, err)
	}
	encoded = append(encoded, '\n')
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	return artifact.Record{Path: artifactPath, Content: encoded}, model.ArtifactReference{Path: artifactPath, SHA256: digest, MediaType: "application/json"}, nil
}

func parseApplications(result QueryResult) (int, error) {
	if err := successfulResult(result); err != nil {
		return 0, err
	}
	var rows []applicationRow
	if err := json.Unmarshal(result.StandardOutput, &rows); err != nil {
		return 0, fmt.Errorf("decode osquery apps JSON: %w", err)
	}
	if rows == nil {
		return 0, fmt.Errorf("decode osquery apps JSON: result array must not be null")
	}
	seenPaths := make(map[string]struct{}, len(rows))
	for index, row := range rows {
		if !filepath.IsAbs(row.Path) {
			return 0, fmt.Errorf("validate osquery apps row %d: path %q must be absolute", index, row.Path)
		}
		if row.Name == "" && row.BundleIdentifier == "" {
			return 0, fmt.Errorf("validate osquery apps row %d: name or bundle_identifier is required", index)
		}
		if _, exists := seenPaths[row.Path]; exists {
			return 0, fmt.Errorf("validate osquery apps row %d: duplicate path %q", index, row.Path)
		}
		seenPaths[row.Path] = struct{}{}
	}
	return len(rows), nil
}

func parseStartupItems(result QueryResult) (int, error) {
	if err := successfulResult(result); err != nil {
		return 0, err
	}
	var rows []startupItemRow
	if err := json.Unmarshal(result.StandardOutput, &rows); err != nil {
		return 0, fmt.Errorf("decode osquery startup_items JSON: %w", err)
	}
	if rows == nil {
		return 0, fmt.Errorf("decode osquery startup_items JSON: result array must not be null")
	}
	for index, row := range rows {
		if strings.TrimSpace(row.Name) == "" || !filepath.IsAbs(row.Path) {
			return 0, fmt.Errorf("validate osquery startup_items row %d: name is required and path %q must be absolute", index, row.Path)
		}
	}
	return len(rows), nil
}

func parseLaunchd(result QueryResult) (int, error) {
	if err := successfulResult(result); err != nil {
		return 0, err
	}
	var rows []launchdRow
	if err := json.Unmarshal(result.StandardOutput, &rows); err != nil {
		return 0, fmt.Errorf("decode osquery launchd JSON: %w", err)
	}
	if rows == nil {
		return 0, fmt.Errorf("decode osquery launchd JSON: result array must not be null")
	}
	seenPaths := make(map[string]struct{}, len(rows))
	for index, row := range rows {
		if !filepath.IsAbs(row.Path) {
			return 0, fmt.Errorf("validate osquery launchd row %d: path %q must be absolute", index, row.Path)
		}
		if _, exists := seenPaths[row.Path]; exists {
			return 0, fmt.Errorf("validate osquery launchd row %d: duplicate path %q", index, row.Path)
		}
		seenPaths[row.Path] = struct{}{}
	}
	return len(rows), nil
}

func parseListeningPorts(result QueryResult) (int, error) {
	if err := successfulResult(result); err != nil {
		return 0, err
	}
	var rows []listeningPortRow
	if err := json.Unmarshal(result.StandardOutput, &rows); err != nil {
		return 0, fmt.Errorf("decode osquery listening_ports JSON: %w", err)
	}
	if rows == nil {
		return 0, fmt.Errorf("decode osquery listening_ports JSON: result array must not be null")
	}
	for index, row := range rows {
		pid, pidErr := strconv.ParseInt(row.PID, 10, 64)
		port, portErr := strconv.ParseUint(row.Port, 10, 16)
		_, protocolErr := strconv.ParseUint(row.Protocol, 10, 16)
		_, familyErr := strconv.ParseUint(row.Family, 10, 16)
		if pidErr != nil || pid < 0 || portErr != nil || port == 0 || protocolErr != nil || familyErr != nil || strings.TrimSpace(row.Address) == "" {
			return 0, fmt.Errorf("validate osquery listening_ports row %d: invalid pid=%q address=%q port=%q protocol=%q family=%q", index, row.PID, row.Address, row.Port, row.Protocol, row.Family)
		}
	}
	return len(rows), nil
}

func parseComplianceValue(result QueryResult) (string, error) {
	if err := successfulResult(result); err != nil {
		return "", err
	}
	var rows []complianceValueRow
	if err := json.Unmarshal(result.StandardOutput, &rows); err != nil {
		return "", fmt.Errorf("decode osquery compliance JSON: %w", err)
	}
	if len(rows) != 1 || strings.TrimSpace(rows[0].Value) == "" {
		return "", fmt.Errorf("validate osquery compliance result: expected one non-empty value row, received %d", len(rows))
	}
	return rows[0].Value, nil
}

func successfulResult(result QueryResult) error {
	if result.ExecutionError != "" || result.ExitCode != 0 {
		return fmt.Errorf("osquery %s failed: exit_code=%d execution_error=%q stderr=%q", result.ID, result.ExitCode, result.ExecutionError, string(result.StandardError))
	}
	if len(result.StandardOutput) == 0 {
		return fmt.Errorf("osquery %s returned empty standard output", result.ID)
	}
	return nil
}
