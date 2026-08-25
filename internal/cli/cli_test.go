package cli

import (
	"errors"
	"testing"
)

func TestParseUnprivilegedScan(t *testing.T) {
	command, err := Parse([]string{"scan", "--output", "/tmp/macscope-test"})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if command.Kind != CommandScan {
		t.Fatalf("command kind = %q, want %q", command.Kind, CommandScan)
	}
	if command.Scan.OutputDirectory != "/tmp/macscope-test" {
		t.Fatalf("output directory = %q, want /tmp/macscope-test", command.Scan.OutputDirectory)
	}
	if command.Scan.PrivilegeRequested {
		t.Fatal("privilege requested = true, want false")
	}
}

func TestParsePrivilegedScan(t *testing.T) {
	command, err := Parse([]string{"scan", "--output", "/tmp/macscope-test", "--privileged"})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if !command.Scan.PrivilegeRequested {
		t.Fatal("privilege requested = false, want true")
	}
}

func TestParseJSONEventScan(t *testing.T) {
	command, err := Parse([]string{"scan", "--output", "/tmp/macscope-test", "--events-json"})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if !command.Scan.EventsJSON {
		t.Fatal("events JSON = false, want true")
	}
}

func TestParseScanWithWritableDataDirectory(t *testing.T) {
	command, err := Parse([]string{"scan", "--output", "/tmp/macscope-test", "--data-directory", "/tmp/macscope-data"})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if command.Scan.DataDirectory != "/tmp/macscope-data" {
		t.Fatalf("data directory = %q, want /tmp/macscope-data", command.Scan.DataDirectory)
	}
}

func TestParseScanWithRepeatedExclusions(t *testing.T) {
	command, err := Parse([]string{"scan", "--output", "/tmp/macscope-test", "--exclude", "/Users/example/Downloads", "--exclude", "/Users/example/example.zip"})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	want := []string{"/Users/example/Downloads", "/Users/example/example.zip"}
	if len(command.Scan.ExcludedPaths) != len(want) {
		t.Fatalf("excluded paths = %#v, want %#v", command.Scan.ExcludedPaths, want)
	}
	for index := range want {
		if command.Scan.ExcludedPaths[index] != want[index] {
			t.Fatalf("excluded path %d = %q, want %q", index, command.Scan.ExcludedPaths[index], want[index])
		}
	}
}

func TestParseReport(t *testing.T) {
	command, err := Parse([]string{"report", "--input", "/tmp/scan.json", "--output", "/tmp/report.html"})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	if command.Kind != CommandReport {
		t.Fatalf("command kind = %q, want %q", command.Kind, CommandReport)
	}
	if command.Report.InputPath != "/tmp/scan.json" || command.Report.OutputPath != "/tmp/report.html" {
		t.Fatalf("report command = %#v, want explicit input and output paths", command.Report)
	}
}

func TestParseReportRequiresInputAndOutput(t *testing.T) {
	for _, arguments := range [][]string{{"report"}, {"report", "--input", "/tmp/scan.json"}, {"report", "--output", "/tmp/report.html"}} {
		_, err := Parse(arguments)
		if err == nil || !IsUsageError(err) {
			t.Fatalf("Parse(%#v) error = %v, want UsageError", arguments, err)
		}
	}
}

func TestParseRequiresOutputDirectory(t *testing.T) {
	_, err := Parse([]string{"scan"})
	if err == nil {
		t.Fatal("Parse returned nil error, want UsageError")
	}
	var usageError UsageError
	if !errors.As(err, &usageError) {
		t.Fatalf("error type = %T, want UsageError", err)
	}
}

func TestParseRejectsUnknownCommand(t *testing.T) {
	_, err := Parse([]string{"unknown"})
	if err == nil {
		t.Fatal("Parse returned nil error, want UsageError")
	}
	if !IsUsageError(err) {
		t.Fatalf("error type = %T, want UsageError", err)
	}
}
