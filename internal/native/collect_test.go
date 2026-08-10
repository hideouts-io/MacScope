package native

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"macscope/internal/model"
)

func TestBuildCollectionCreatesFindingsArtifactsAndCoverageGaps(t *testing.T) {
	unprivilegedResults := completeUnprivilegedResults()
	observedAt := unprivilegedResults[len(unprivilegedResults)-1].CompletedAt.Add(time.Millisecond)
	collection, err := BuildCollection(unprivilegedResults, make([]ProbeResult, 0), false, observedAt)
	if err != nil {
		t.Fatalf("BuildCollection returned an error: %v", err)
	}
	if len(collection.Coverage) != 14 {
		t.Fatalf("coverage count = %d, want 14", len(collection.Coverage))
	}
	if len(collection.Evidence) != 14 {
		t.Fatalf("evidence count = %d, want 14", len(collection.Evidence))
	}
	if len(collection.Artifacts) != 12 {
		t.Fatalf("artifact count = %d, want 12", len(collection.Artifacts))
	}
	if len(collection.Findings) != 3 {
		t.Fatalf("finding count = %d, want 3", len(collection.Findings))
	}
	if collection.Findings[0].ID != "finding.native.application-firewall" {
		t.Fatalf("first finding ID = %q, want application firewall finding", collection.Findings[0].ID)
	}
	if collection.Findings[1].Category != model.FindingCategoryCoverageGap || collection.Findings[2].Category != model.FindingCategoryCoverageGap {
		t.Fatalf("privileged findings are not coverage gaps: %#v", collection.Findings[1:])
	}
	if collection.HostDetails.MacOSVersion != "26.4" || collection.HostDetails.ModelID != "Mac15,10" {
		t.Fatalf("host details = %#v, want parsed macOS and hardware identity", collection.HostDetails)
	}

	for index, artifact := range collection.Artifacts {
		actualDigest := fmt.Sprintf("%x", sha256.Sum256(artifact.Content))
		expectedDigest := collection.Evidence[index].Artifact.SHA256
		if actualDigest != expectedDigest {
			t.Fatalf("artifact %q digest = %s, want %s", artifact.Path, actualDigest, expectedDigest)
		}
	}
}

func TestBuildCollectionTurnsProbeFailureIntoExplicitFinding(t *testing.T) {
	results := completeUnprivilegedResults()
	results[3].ExitCode = 15
	results[3].ExecutionError = "exit status 15"
	results[3].StandardOutput = make([]byte, 0)
	results[3].StandardError = []byte("Error: Unknown volume or device specifier: '/'.\n")

	collection, err := BuildCollection(results, make([]ProbeResult, 0), false, results[len(results)-1].CompletedAt.Add(time.Millisecond))
	if err != nil {
		t.Fatalf("BuildCollection returned an error: %v", err)
	}
	if collection.Coverage[3].Status != model.CoverageStatusFailed {
		t.Fatalf("FileVault coverage status = %q, want failed", collection.Coverage[3].Status)
	}
	foundToolError := false
	for _, finding := range collection.Findings {
		if finding.ID == "finding.native.filevault.tool-error" {
			foundToolError = true
		}
	}
	if !foundToolError {
		t.Fatal("FileVault tool-error finding was not produced")
	}
}

func TestValidatePrivilegedResultsRejectsTamperedCommand(t *testing.T) {
	results := completePrivilegedResults()
	results[0].Executable = "/tmp/not-pfctl"
	if err := ValidatePrivilegedResults(results); err == nil {
		t.Fatal("ValidatePrivilegedResults returned nil error for tampered executable")
	}
}

func completeUnprivilegedResults() []ProbeResult {
	outputs := []string{
		"ProductName:\t\tmacOS\nProductVersion:\t\t26.4\nBuildVersion:\t\t25E246\n",
		`{"SPHardwareDataType":[{"machine_model":"Mac15,10","chip_type":"Apple M3 Max"}]}`,
		"System Integrity Protection status: enabled.\n",
		"FileVault is On.\n",
		"assessments enabled\n",
		"Firewall is disabled. (State = 0)\n",
		"Firewall stealth mode is off\n",
		"Firewall has block all state set to disabled.\n",
		"Automatic checking for updates is turned on\n",
		"5354\n",
		"157\n",
		"74\n",
	}
	return resultsForSpecs(unprivilegedProbeSpecs(), outputs)
}

func completePrivilegedResults() []ProbeResult {
	outputs := []string{
		"Status: Enabled for 0 days 00:01:00\n",
		"Remote Login: Off\n",
	}
	return resultsForSpecs(privilegedProbeSpecs(), outputs)
}

func resultsForSpecs(specs []probeSpec, outputs []string) []ProbeResult {
	startedAt := time.Date(2026, time.August, 9, 10, 0, 0, 0, time.UTC)
	results := make([]ProbeResult, 0, len(specs))
	for index, spec := range specs {
		results = append(results, ProbeResult{
			ID:             spec.ID,
			Executable:     spec.Executable,
			Arguments:      append([]string(nil), spec.Arguments...),
			Privileged:     spec.Privileged,
			StartedAt:      startedAt.Add(time.Duration(index) * time.Millisecond),
			CompletedAt:    startedAt.Add(time.Duration(index+1) * time.Millisecond),
			ExitCode:       0,
			StandardOutput: []byte(outputs[index]),
			StandardError:  make([]byte, 0),
			ExecutionError: "",
		})
	}
	return results
}
