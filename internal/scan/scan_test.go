package scan

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"macscope/internal/cli"
	"macscope/internal/eventstream"
	"macscope/internal/model"
	osquerycollector "macscope/internal/osquery"
	"macscope/internal/progress"
	"macscope/internal/sofa"
	"macscope/internal/supplychain"
)

func TestRunWritesUnprivilegedSchemaValidatedReport(t *testing.T) {
	outputDirectory := filepath.Join(t.TempDir(), "results")
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	command := cli.ScanCommand{
		OutputDirectory:    outputDirectory,
		PrivilegeRequested: false,
	}

	sofaClient, closeServer := invalidFeedSOFAClient(t)
	defer closeServer()
	osqueryClient := unavailableOsqueryClient(t)
	supplyChainClient := unavailableSupplyChainClient(t)
	events := make([]progress.Event, 0)
	progressTracker := progress.Disabled(os.Stderr)
	progressTracker.Report = func(event progress.Event) error {
		events = append(events, event)
		return nil
	}
	result, err := run(context.Background(), command, executable, 501, strings.NewReader(""), os.Stderr, sofaClient, osqueryClient, supplyChainClient, progressTracker, eventstream.Disabled())
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}

	file, err := os.Open(result.ReportPath)
	if err != nil {
		t.Fatalf("open report: %v", err)
	}
	run, decodeErr := model.DecodeScanRun(file)
	closeErr := file.Close()
	if decodeErr != nil {
		t.Fatalf("decode report: %v", decodeErr)
	}
	if closeErr != nil {
		t.Fatalf("close report: %v", closeErr)
	}
	if run.Status != model.RunStatusPartial {
		t.Fatalf("status = %q, want partial because privileged probes were not requested", run.Status)
	}
	if run.Privilege.Requested || run.Privilege.Granted {
		t.Fatalf("privilege evidence = requested:%t granted:%t, want false/false", run.Privilege.Requested, run.Privilege.Granted)
	}
	if len(run.Tools) != 2 || run.Tools[0].ID != "macscope" || run.Tools[0].Executable == nil || run.Tools[1].ID != "mscp" {
		t.Fatalf("tools = %#v, want MacScope and the pinned mSCP data tool after external collectors are rejected", run.Tools)
	}
	if !hasCoverage(run.Coverage, "coverage.sofa.failure", model.CoverageStatusFailed) {
		t.Fatalf("coverage = %#v, want explicit SOFA failure coverage", run.Coverage)
	}
	if len(events) == 0 || events[0].Percent != 2 || events[len(events)-1].Percent != 100 {
		t.Fatalf("progress events = %#v, want scan milestones from 2 through 100 percent", events)
	}
	if events[0].CollectorID != "macscope" {
		t.Fatalf("first progress collector = %q, want macscope", events[0].CollectorID)
	}
}

func TestRunDoesNotOverwriteExistingEvidence(t *testing.T) {
	outputDirectory := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	reportPath := filepath.Join(outputDirectory, "scan.json")
	if err := os.WriteFile(reportPath, []byte("preserve"), 0o640); err != nil {
		t.Fatalf("create existing report: %v", err)
	}

	command := cli.ScanCommand{
		OutputDirectory:    outputDirectory,
		PrivilegeRequested: false,
	}
	sofaClient, closeServer := invalidFeedSOFAClient(t)
	defer closeServer()
	osqueryClient := unavailableOsqueryClient(t)
	supplyChainClient := unavailableSupplyChainClient(t)
	_, err = run(context.Background(), command, executable, 501, strings.NewReader(""), os.Stderr, sofaClient, osqueryClient, supplyChainClient, progress.Disabled(os.Stderr), eventstream.Disabled())
	if err == nil {
		t.Fatal("Run returned nil error, want OutputError")
	}

	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatalf("read existing report: %v", readErr)
	}
	if string(data) != "preserve" {
		t.Fatalf("existing report = %q, want preserve", string(data))
	}
}

func invalidFeedSOFAClient(t *testing.T) (sofa.Client, func()) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{}`)
	}))
	client, err := sofa.NewClient(sofa.ClientConfig{
		Endpoint:         server.URL,
		UserAgent:        "MacScope/scan-test",
		Attempts:         1,
		RetryDelays:      make([]time.Duration, 0),
		MaxResponseBytes: 1024,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		server.Close()
		t.Fatalf("configure test SOFA client: %v", err)
	}
	return client, server.Close
}

func unavailableOsqueryClient(t *testing.T) osquerycollector.Client {
	t.Helper()
	client, err := osquerycollector.NewClient(osquerycollector.ClientConfig{
		ExecutablePath:  filepath.Join(t.TempDir(), "missing-osqueryi"),
		ExpectedVersion: osquerycollector.ExpectedVersion,
		ExpectedSHA256:  osquerycollector.ExpectedExecutableHash,
		QueryTimeout:    time.Second,
		EventEmitter:    eventstream.Disabled(),
	})
	if err != nil {
		t.Fatalf("configure unavailable test osquery client: %v", err)
	}
	return client
}

func unavailableSupplyChainClient(t *testing.T) supplychain.Client {
	t.Helper()
	root := t.TempDir()
	client, err := supplychain.NewClient(supplychain.ClientConfig{
		SyftExecutablePath:     filepath.Join(root, "missing-syft"),
		SyftExpectedVersion:    supplychain.SyftExpectedVersion,
		SyftExpectedCommit:     supplychain.SyftExpectedCommit,
		SyftExpectedSHA256:     supplychain.SyftExpectedExecutableHash,
		SyftConfigPath:         filepath.Join(root, "missing-syft.yaml"),
		GrypeExecutablePath:    filepath.Join(root, "missing-grype"),
		GrypeExpectedVersion:   supplychain.GrypeExpectedVersion,
		GrypeExpectedCommit:    supplychain.GrypeExpectedCommit,
		GrypeExpectedSHA256:    supplychain.GrypeExpectedExecutableHash,
		GrypeConfigPath:        filepath.Join(root, "missing-grype.yaml"),
		GrypeDatabaseDirectory: filepath.Join(root, "missing-db"),
		SyftTimeout:            time.Second,
		GrypeTimeout:           time.Second,
		DatabaseTimeout:        time.Second,
		DatabaseUpdateAttempts: 1,
		DatabaseRetryDelays:    make([]time.Duration, 0),
		EventEmitter:           eventstream.Disabled(),
	})
	if err != nil {
		t.Fatalf("configure unavailable supply-chain client: %v", err)
	}
	return client
}

func hasCoverage(records []model.CoverageRecord, identifier string, status model.CoverageStatus) bool {
	for _, record := range records {
		if record.ID == identifier && record.Status == status {
			return true
		}
	}
	return false
}

func TestRunRejectsRootOrchestrator(t *testing.T) {
	command := cli.ScanCommand{
		OutputDirectory:    t.TempDir(),
		PrivilegeRequested: true,
	}

	_, err := Run(context.Background(), command, "/tmp/macscope", 0, strings.NewReader(""), os.Stderr, progress.Disabled(os.Stderr), eventstream.Disabled())
	if err == nil {
		t.Fatal("Run returned nil error, want ExecutionIdentityError")
	}
	if _, ok := err.(ExecutionIdentityError); !ok {
		t.Fatalf("error type = %T, want ExecutionIdentityError", err)
	}
}

func TestRunRejectsInvalidExclusionBeforeCollection(t *testing.T) {
	command := cli.ScanCommand{
		OutputDirectory:    t.TempDir(),
		PrivilegeRequested: false,
		ExcludedPaths:      []string{"relative/path"},
	}
	sofaClient, closeServer := invalidFeedSOFAClient(t)
	defer closeServer()
	_, err := run(context.Background(), command, "/tmp/macscope", 501, strings.NewReader(""), os.Stderr, sofaClient, unavailableOsqueryClient(t), unavailableSupplyChainClient(t), progress.Disabled(os.Stderr), eventstream.Disabled())
	if err == nil || !strings.Contains(err.Error(), "path must be absolute") {
		t.Fatalf("run error = %v, want absolute exclusion path validation error", err)
	}
}

func TestRunRejectsCanceledContextBeforeCollection(t *testing.T) {
	parentContext, cancel := context.WithCancel(context.Background())
	cancel()
	command := cli.ScanCommand{
		OutputDirectory:    t.TempDir(),
		PrivilegeRequested: false,
	}
	sofaClient, closeServer := invalidFeedSOFAClient(t)
	defer closeServer()
	_, err := run(parentContext, command, "/tmp/macscope", 501, strings.NewReader(""), os.Stderr, sofaClient, unavailableOsqueryClient(t), unavailableSupplyChainClient(t), progress.Disabled(os.Stderr), eventstream.Disabled())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run error = %v, want context.Canceled", err)
	}
}

func TestDeriveRunStatus(t *testing.T) {
	completeCoverage := []model.CoverageRecord{{Status: model.CoverageStatusComplete}}
	if status := deriveRunStatus(completeCoverage); status != model.RunStatusCompleted {
		t.Fatalf("complete coverage status = %q, want completed", status)
	}
	partialCoverage := []model.CoverageRecord{
		{Status: model.CoverageStatusComplete},
		{Status: model.CoverageStatusNotScanned},
	}
	if status := deriveRunStatus(partialCoverage); status != model.RunStatusPartial {
		t.Fatalf("incomplete coverage status = %q, want partial", status)
	}
}

func TestCollectionCopiesPreserveEmptyJSONArrays(t *testing.T) {
	coverage := copyCoverageRecords(make([]model.CoverageRecord, 0))
	evidence := copyEvidenceRecords(make([]model.EvidenceRecord, 0))
	findings := copyFindings(make([]model.Finding, 0))
	if coverage == nil {
		t.Fatal("copied coverage is nil, want non-nil empty slice")
	}
	if evidence == nil {
		t.Fatal("copied evidence is nil, want non-nil empty slice")
	}
	if findings == nil {
		t.Fatal("copied findings is nil, want non-nil empty slice")
	}
	payload := struct {
		Coverage []model.CoverageRecord `json:"coverage"`
		Evidence []model.EvidenceRecord `json:"evidence"`
		Findings []model.Finding        `json:"findings"`
	}{
		Coverage: coverage,
		Evidence: evidence,
		Findings: findings,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode copied collections: %v", err)
	}
	expected := `{"coverage":[],"evidence":[],"findings":[]}`
	if string(encoded) != expected {
		t.Fatalf("encoded collections = %s, want %s", encoded, expected)
	}
}
