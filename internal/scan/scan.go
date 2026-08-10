package scan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"macscope/internal/artifact"
	"macscope/internal/cli"
	"macscope/internal/model"
	"macscope/internal/native"
	osquerycollector "macscope/internal/osquery"
	"macscope/internal/privilege"
	"macscope/internal/sofa"
	"macscope/internal/supplychain"
	"macscope/internal/version"
)

type Result struct {
	ReportPath string
}

type OutputError struct {
	Path  string
	Cause error
}

func (err OutputError) Error() string {
	return fmt.Sprintf("write scan output %q: %v", err.Path, err.Cause)
}

func (err OutputError) Unwrap() error {
	return err.Cause
}

type ExecutionIdentityError struct {
	EffectiveUID int
}

func (err ExecutionIdentityError) Error() string {
	return fmt.Sprintf("MacScope orchestrator must not run as root; effective UID is %d; run MacScope as the signed-in user and add --privileged for narrow sudo collectors", err.EffectiveUID)
}

type RuntimeEvidenceError struct {
	Operation string
	Cause     error
}

func (err RuntimeEvidenceError) Error() string {
	return fmt.Sprintf("collect scanner runtime evidence during %s: %v", err.Operation, err.Cause)
}

func (err RuntimeEvidenceError) Unwrap() error {
	return err.Cause
}

func Run(command cli.ScanCommand, executable string, effectiveUID int, stdin io.Reader, stderr io.Writer) (Result, error) {
	sofaClient, err := sofa.NewClient(sofa.ClientConfig{
		Endpoint:         sofa.FeedURL,
		UserAgent:        "MacScope/" + version.Current + " (SOFA v2 security posture integration)",
		Attempts:         3,
		RetryDelays:      []time.Duration{250 * time.Millisecond, 500 * time.Millisecond},
		MaxResponseBytes: 8 * 1024 * 1024,
		HTTPClient:       &http.Client{Timeout: 20 * time.Second},
	})
	if err != nil {
		return Result{}, fmt.Errorf("configure SOFA client: %w", err)
	}
	absoluteExecutable, err := filepath.Abs(executable)
	if err != nil {
		return Result{}, RuntimeEvidenceError{Operation: "resolving executable path for project tools", Cause: err}
	}
	projectRoot := filepath.Dir(filepath.Dir(absoluteExecutable))
	osqueryClient, err := osquerycollector.NewClient(osquerycollector.ClientConfig{
		ExecutablePath:  filepath.Join(projectRoot, ".tools", "osquery", osquerycollector.ExpectedVersion, "osqueryi"),
		ExpectedVersion: osquerycollector.ExpectedVersion,
		ExpectedSHA256:  osquerycollector.ExpectedExecutableHash,
		QueryTimeout:    30 * time.Second,
	})
	if err != nil {
		return Result{}, fmt.Errorf("configure osquery client: %w", err)
	}
	supplyChainClient, err := supplychain.NewClient(supplychain.ClientConfig{
		SyftExecutablePath:     filepath.Join(projectRoot, ".tools", "syft", supplychain.SyftExpectedVersion, "syft"),
		SyftExpectedVersion:    supplychain.SyftExpectedVersion,
		SyftExpectedCommit:     supplychain.SyftExpectedCommit,
		SyftExpectedSHA256:     supplychain.SyftExpectedExecutableHash,
		SyftConfigPath:         filepath.Join(projectRoot, "config", "syft.yaml"),
		GrypeExecutablePath:    filepath.Join(projectRoot, ".tools", "grype", supplychain.GrypeExpectedVersion, "grype"),
		GrypeExpectedVersion:   supplychain.GrypeExpectedVersion,
		GrypeExpectedCommit:    supplychain.GrypeExpectedCommit,
		GrypeExpectedSHA256:    supplychain.GrypeExpectedExecutableHash,
		GrypeConfigPath:        filepath.Join(projectRoot, "config", "grype.yaml"),
		GrypeDatabaseDirectory: filepath.Join(projectRoot, ".tools", "grype", "db"),
		SyftTimeout:            30 * time.Minute,
		GrypeTimeout:           10 * time.Minute,
		DatabaseTimeout:        10 * time.Minute,
		DatabaseUpdateAttempts: 3,
		DatabaseRetryDelays:    []time.Duration{time.Second, 2 * time.Second},
	})
	if err != nil {
		return Result{}, fmt.Errorf("configure Syft and Grype client: %w", err)
	}
	return run(command, executable, effectiveUID, stdin, stderr, sofaClient, osqueryClient, supplyChainClient)
}

func run(command cli.ScanCommand, executable string, effectiveUID int, stdin io.Reader, stderr io.Writer, sofaClient sofa.Client, osqueryClient osquerycollector.Client, supplyChainClient supplychain.Client) (Result, error) {
	if effectiveUID == 0 {
		return Result{}, ExecutionIdentityError{EffectiveUID: effectiveUID}
	}
	if err := supplychain.ValidateExcludedPaths(command.ExcludedPaths); err != nil {
		return Result{}, fmt.Errorf("validate user-selected filesystem exclusions: %w", err)
	}

	startedAt := time.Now().UTC()
	unprivilegedResults := native.CollectUnprivileged(context.Background())
	privilegedResults := make([]native.ProbeResult, 0)
	privilegeEvidence := model.PrivilegeEvidence{
		Requested:                command.PrivilegeRequested,
		Granted:                  false,
		Collector:                "none",
		OrchestratorEffectiveUID: effectiveUID,
		CollectorEffectiveUID:    nil,
	}

	if command.PrivilegeRequested {
		privilegedResult, err := privilege.Collect(executable, effectiveUID, stdin, stderr)
		if err != nil {
			return Result{}, err
		}
		privilegeEvidence = model.PrivilegeEvidence{
			Requested:                true,
			Granted:                  privilegedResult.Granted,
			Collector:                privilegedResult.Collector,
			OrchestratorEffectiveUID: effectiveUID,
			CollectorEffectiveUID:    intPointer(privilegedResult.EffectiveUID),
		}
		privilegedResults = append(privilegedResults, privilegedResult.NativeResults...)
	}
	nativeCollection, err := native.BuildCollection(unprivilegedResults, privilegedResults, command.PrivilegeRequested, time.Now().UTC())
	if err != nil {
		return Result{}, err
	}
	sofaResponse, fetchErr := sofaClient.Fetch(context.Background(), stderr)
	var sofaCollection sofa.Collection
	if fetchErr != nil {
		sofaCollection = sofa.BuildFailure(sofaResponse, fetchErr)
	} else {
		sofaCollection, err = sofa.BuildCollection(sofaResponse, sofa.LocalState{
			MacOSVersion:          nativeCollection.HostDetails.MacOSVersion,
			MacOSBuild:            nativeCollection.HostDetails.MacOSBuild,
			XProtectConfigVersion: nativeCollection.HostDetails.XProtectConfigVersion,
			XProtectVersion:       nativeCollection.HostDetails.XProtectVersion,
			XProtectPluginVersion: nativeCollection.HostDetails.XProtectPluginVersion,
		})
		if err != nil {
			sofaCollection = sofa.BuildFailure(sofaResponse, err)
		}
	}
	osqueryCollection, err := osquerycollector.Collect(context.Background(), osqueryClient, nativeCollection.HostDetails.MacOSVersion, time.Now().UTC())
	if err != nil {
		return Result{}, fmt.Errorf("collect osquery and mSCP evidence: %w", err)
	}
	supplyChainCollection, err := supplychain.Collect(context.Background(), supplyChainClient, nativeCollection.HostDetails.MacOSVersion, command.ExcludedPaths, stderr, time.Now().UTC())
	if err != nil {
		return Result{}, fmt.Errorf("collect Syft and Grype evidence: %w", err)
	}

	runID, err := generateRunID()
	if err != nil {
		return Result{}, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return Result{}, RuntimeEvidenceError{Operation: "resolving hostname", Cause: err}
	}
	absoluteExecutable, err := filepath.Abs(executable)
	if err != nil {
		return Result{}, RuntimeEvidenceError{Operation: "resolving executable path", Cause: err}
	}
	executableDigest, err := hashFile(absoluteExecutable)
	if err != nil {
		return Result{}, err
	}
	coverage := appendCoverageRecords(nativeCollection.Coverage, sofaCollection.Coverage)
	coverage = appendCoverageRecords(coverage, osqueryCollection.Coverage)
	coverage = appendCoverageRecords(coverage, supplyChainCollection.Coverage)
	evidence := appendEvidenceRecords(nativeCollection.Evidence, sofaCollection.Evidence)
	evidence = appendEvidenceRecords(evidence, osqueryCollection.Evidence)
	evidence = appendEvidenceRecords(evidence, supplyChainCollection.Evidence)
	findings := appendFindings(nativeCollection.Findings, sofaCollection.Findings)
	findings = appendFindings(findings, osqueryCollection.Findings)
	findings = appendFindings(findings, supplyChainCollection.Findings)
	artifacts := appendArtifacts(nativeCollection.Artifacts, sofaCollection.Artifacts)
	artifacts = appendArtifacts(artifacts, osqueryCollection.Artifacts)
	artifacts = appendArtifacts(artifacts, supplyChainCollection.Artifacts)
	tools := append([]model.ToolRecord{
		{
			ID:      "macscope",
			Name:    "MacScope",
			Version: version.Current,
			Kind:    model.ToolKindScanner,
			Executable: &model.ExecutableIdentity{
				Path:   absoluteExecutable,
				SHA256: executableDigest,
			},
		},
	}, sofaCollection.Tools...)
	tools = append(tools, osqueryCollection.Tools...)
	tools = append(tools, supplyChainCollection.Tools...)

	completedAt := time.Now().UTC()
	run := model.ScanRun{
		SchemaVersion: model.ScanSchemaVersion,
		RunID:         runID,
		Scanner: model.ScannerIdentity{
			Name:    "MacScope",
			Version: version.Current,
		},
		Host: model.HostIdentity{
			Hostname:     hostname,
			OperatingOS:  runtime.GOOS,
			Architecture: runtime.GOARCH,
			MacOSVersion: nativeCollection.HostDetails.MacOSVersion,
			MacOSBuild:   nativeCollection.HostDetails.MacOSBuild,
			ModelID:      nativeCollection.HostDetails.ModelID,
			Chip:         nativeCollection.HostDetails.Chip,
		},
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Status:      deriveRunStatus(coverage),
		Privilege:   privilegeEvidence,
		Tools:       tools,
		Coverage:    coverage,
		Evidence:    evidence,
		Findings:    findings,
	}

	reportPath, err := writeReport(command.OutputDirectory, run, artifacts)
	if err != nil {
		return Result{}, err
	}
	return Result{ReportPath: reportPath}, nil
}

func writeReport(outputDirectory string, run model.ScanRun, artifacts []artifact.Record) (string, error) {
	if err := model.ValidateScanRun(run); err != nil {
		return "", OutputError{Path: outputDirectory, Cause: err}
	}
	if err := validateArtifacts(run.Evidence, artifacts); err != nil {
		return "", OutputError{Path: outputDirectory, Cause: err}
	}
	absoluteDirectory, err := filepath.Abs(outputDirectory)
	if err != nil {
		return "", OutputError{Path: outputDirectory, Cause: fmt.Errorf("resolve absolute output directory: %w", err)}
	}
	if err := os.MkdirAll(absoluteDirectory, 0o750); err != nil {
		return "", OutputError{Path: absoluteDirectory, Cause: fmt.Errorf("create output directory: %w", err)}
	}
	reportPath := filepath.Join(absoluteDirectory, "scan.json")
	if _, err := os.Lstat(reportPath); err == nil {
		return "", OutputError{Path: reportPath, Cause: fmt.Errorf("report already exists; choose a new output directory to preserve evidence")}
	} else if !os.IsNotExist(err) {
		return "", OutputError{Path: reportPath, Cause: fmt.Errorf("inspect existing report path: %w", err)}
	}
	for _, artifact := range artifacts {
		artifactPath := filepath.Join(absoluteDirectory, artifact.Path)
		if err := os.MkdirAll(filepath.Dir(artifactPath), 0o750); err != nil {
			return "", OutputError{Path: artifactPath, Cause: fmt.Errorf("create artifact directory: %w", err)}
		}
		if err := writeExclusiveFile(artifactPath, artifact.Content); err != nil {
			return "", OutputError{Path: artifactPath, Cause: err}
		}
	}

	file, err := os.OpenFile(reportPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return "", OutputError{Path: reportPath, Cause: fmt.Errorf("create report without overwriting existing evidence: %w", err)}
	}

	if err := model.EncodeScanRun(file, run); err != nil {
		closeErr := file.Close()
		if closeErr != nil {
			return "", OutputError{Path: reportPath, Cause: fmt.Errorf("encode report: %v; close incomplete report: %w", err, closeErr)}
		}
		return "", OutputError{Path: reportPath, Cause: fmt.Errorf("encode report: %w", err)}
	}
	if err := file.Sync(); err != nil {
		closeErr := file.Close()
		if closeErr != nil {
			return "", OutputError{Path: reportPath, Cause: fmt.Errorf("sync report: %v; close report: %w", err, closeErr)}
		}
		return "", OutputError{Path: reportPath, Cause: fmt.Errorf("sync report: %w", err)}
	}
	if err := file.Close(); err != nil {
		return "", OutputError{Path: reportPath, Cause: fmt.Errorf("close report: %w", err)}
	}
	return reportPath, nil
}

func validateArtifacts(evidence []model.EvidenceRecord, artifacts []artifact.Record) error {
	expectedDigests := make(map[string]string)
	for _, record := range evidence {
		if record.Artifact == nil {
			continue
		}
		if _, exists := expectedDigests[record.Artifact.Path]; exists {
			return fmt.Errorf("multiple evidence records reference artifact path %q", record.Artifact.Path)
		}
		expectedDigests[record.Artifact.Path] = record.Artifact.SHA256
	}
	seenArtifacts := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if _, exists := seenArtifacts[artifact.Path]; exists {
			return fmt.Errorf("duplicate artifact content for path %q", artifact.Path)
		}
		seenArtifacts[artifact.Path] = struct{}{}
		expectedDigest, exists := expectedDigests[artifact.Path]
		if !exists {
			return fmt.Errorf("artifact path %q is not referenced by evidence", artifact.Path)
		}
		actualDigest := fmt.Sprintf("%x", sha256.Sum256(artifact.Content))
		if actualDigest != expectedDigest {
			return fmt.Errorf("artifact path %q SHA-256 mismatch: expected %s, calculated %s", artifact.Path, expectedDigest, actualDigest)
		}
	}
	if len(seenArtifacts) != len(expectedDigests) {
		return fmt.Errorf("received %d artifact files for %d evidence artifact references", len(seenArtifacts), len(expectedDigests))
	}
	return nil
}

func writeExclusiveFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return fmt.Errorf("create file without overwriting existing evidence: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		closeErr := file.Close()
		if closeErr != nil {
			return fmt.Errorf("write file: %v; close incomplete file: %w", err, closeErr)
		}
		return fmt.Errorf("write file: %w", err)
	}
	if err := file.Sync(); err != nil {
		closeErr := file.Close()
		if closeErr != nil {
			return fmt.Errorf("sync file: %v; close file: %w", err, closeErr)
		}
		return fmt.Errorf("sync file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}
	return nil
}

func generateRunID() (string, error) {
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		return "", RuntimeEvidenceError{Operation: "generating run ID", Cause: err}
	}
	identifier[6] = (identifier[6] & 0x0f) | 0x40
	identifier[8] = (identifier[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", identifier[0:4], identifier[4:6], identifier[6:8], identifier[8:10], identifier[10:16]), nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", RuntimeEvidenceError{Operation: "opening executable for SHA-256", Cause: err}
	}

	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil {
		if closeErr != nil {
			return "", RuntimeEvidenceError{Operation: "hashing executable", Cause: fmt.Errorf("copy bytes: %v; close executable: %w", copyErr, closeErr)}
		}
		return "", RuntimeEvidenceError{Operation: "hashing executable", Cause: copyErr}
	}
	if closeErr != nil {
		return "", RuntimeEvidenceError{Operation: "closing executable after SHA-256", Cause: closeErr}
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

func intPointer(value int) *int {
	pointerValue := value
	return &pointerValue
}

func deriveRunStatus(coverage []model.CoverageRecord) model.RunStatus {
	for _, record := range coverage {
		if record.Status != model.CoverageStatusComplete {
			return model.RunStatusPartial
		}
	}
	return model.RunStatusCompleted
}

func copyCoverageRecords(records []model.CoverageRecord) []model.CoverageRecord {
	copied := make([]model.CoverageRecord, len(records))
	copy(copied, records)
	return copied
}

func copyEvidenceRecords(records []model.EvidenceRecord) []model.EvidenceRecord {
	copied := make([]model.EvidenceRecord, len(records))
	copy(copied, records)
	return copied
}

func copyFindings(findings []model.Finding) []model.Finding {
	copied := make([]model.Finding, len(findings))
	copy(copied, findings)
	return copied
}

func appendCoverageRecords(first []model.CoverageRecord, second []model.CoverageRecord) []model.CoverageRecord {
	combined := make([]model.CoverageRecord, 0, len(first)+len(second))
	combined = append(combined, first...)
	return append(combined, second...)
}

func appendEvidenceRecords(first []model.EvidenceRecord, second []model.EvidenceRecord) []model.EvidenceRecord {
	combined := make([]model.EvidenceRecord, 0, len(first)+len(second))
	combined = append(combined, first...)
	return append(combined, second...)
}

func appendFindings(first []model.Finding, second []model.Finding) []model.Finding {
	combined := make([]model.Finding, 0, len(first)+len(second))
	combined = append(combined, first...)
	return append(combined, second...)
}

func appendArtifacts(first []artifact.Record, second []artifact.Record) []artifact.Record {
	combined := make([]artifact.Record, 0, len(first)+len(second))
	combined = append(combined, first...)
	return append(combined, second...)
}
