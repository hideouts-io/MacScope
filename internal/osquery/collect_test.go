package osquery

import (
	"strings"
	"testing"
	"time"
)

func TestParseApplicationsValidatesRequiredIdentity(t *testing.T) {
	result := successfulQueryResult("apps", `[{"name":"Example.app","path":"/Applications/Example.app","bundle_identifier":"com.example.app","bundle_short_version":"1.0","bundle_version":"1"}]`)
	count, err := parseApplications(result)
	if err != nil {
		t.Fatalf("parseApplications returned an error: %v", err)
	}
	if count != 1 {
		t.Fatalf("application count = %d, want 1", count)
	}
	result.StandardOutput = []byte(`[{"name":"","path":"relative.app","bundle_identifier":"","bundle_short_version":"","bundle_version":""}]`)
	_, err = parseApplications(result)
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("parseApplications error = %v, want absolute-path validation error", err)
	}
}

func TestParseComplianceValueRequiresExactlyOneRow(t *testing.T) {
	result := successfulQueryResult("mscp-test", `[{"value":"1"}]`)
	value, err := parseComplianceValue(result)
	if err != nil {
		t.Fatalf("parseComplianceValue returned an error: %v", err)
	}
	if value != "1" {
		t.Fatalf("value = %q, want 1", value)
	}
	result.StandardOutput = []byte(`[]`)
	_, err = parseComplianceValue(result)
	if err == nil {
		t.Fatal("parseComplianceValue returned nil error for empty result")
	}
}

func TestParseVersionRejectsMislabeledReleaseBinary(t *testing.T) {
	version, err := parseVersion([]byte("osqueryi version 5.21.0\n"))
	if err != nil || version != "5.21.0" {
		t.Fatalf("version/error = %q/%v, want 5.21.0/nil", version, err)
	}
	if _, err := parseVersion([]byte("5.21.0\n")); err == nil {
		t.Fatal("parseVersion returned nil error for unrecognized output")
	}
}

func successfulQueryResult(identifier string, output string) QueryResult {
	startedAt := time.Date(2026, time.August, 9, 20, 0, 0, 0, time.UTC)
	return QueryResult{
		ID:             identifier,
		Arguments:      []string{"--json", "SELECT 1;"},
		StartedAt:      startedAt,
		CompletedAt:    startedAt.Add(time.Millisecond),
		ExitCode:       0,
		StandardOutput: []byte(output),
		StandardError:  make([]byte, 0),
		ExecutionError: "",
	}
}
