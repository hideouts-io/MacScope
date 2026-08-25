package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"macscope/internal/eventstream"
	"macscope/internal/progress"
)

func TestJSONEventsRequestedOnlyForScanFlag(t *testing.T) {
	testCases := []struct {
		name      string
		arguments []string
		want      bool
	}{
		{name: "scan events", arguments: []string{"scan", "--output", "/tmp/results", "--events-json"}, want: true},
		{name: "scan events explicit true", arguments: []string{"scan", "--events-json=true", "--output", "/tmp/results"}, want: true},
		{name: "scan events explicit false", arguments: []string{"scan", "--events-json=false", "--output", "/tmp/results"}, want: false},
		{name: "flag text consumed as output value", arguments: []string{"scan", "--output", "--events-json"}, want: false},
		{name: "normal scan", arguments: []string{"scan", "--output", "/tmp/results"}, want: false},
		{name: "report argument", arguments: []string{"report", "--input", "--events-json"}, want: false},
		{name: "no arguments", arguments: make([]string, 0), want: false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := jsonEventsRequested(testCase.arguments); got != testCase.want {
				t.Fatalf("jsonEventsRequested(%#v) = %t, want %t", testCase.arguments, got, testCase.want)
			}
		})
	}
}

func TestCanceledJSONEventScanEmitsTerminalFailure(t *testing.T) {
	parentContext, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	now := time.Date(2026, time.August, 24, 20, 14, 0, 0, time.UTC)
	emit, err := eventstream.NewNDJSON(&stdout, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewNDJSON returned an error: %v", err)
	}
	exitCode := run(
		parentContext,
		[]string{"scan", "--output", t.TempDir(), "--events-json"},
		&stdout,
		&stderr,
		progress.Disabled(&stderr),
		emit,
	)
	if exitCode != 130 {
		t.Fatalf("exit code = %d, want 130; stderr=%q", exitCode, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("event lines = %d, want 2: %q", len(lines), stdout.String())
	}
	var started eventstream.Envelope
	if err := json.Unmarshal([]byte(lines[0]), &started); err != nil {
		t.Fatalf("decode scan_started event: %v", err)
	}
	var failed eventstream.Envelope
	if err := json.Unmarshal([]byte(lines[1]), &failed); err != nil {
		t.Fatalf("decode scan_failed event: %v", err)
	}
	if started.Type != eventstream.TypeScanStarted {
		t.Fatalf("first event type = %q, want %q", started.Type, eventstream.TypeScanStarted)
	}
	if failed.Type != eventstream.TypeScanFailed || failed.ScanFailed == nil || failed.ScanFailed.ErrorType != "canceled" {
		t.Fatalf("final event = %#v, want canceled scan_failed", failed)
	}
}
