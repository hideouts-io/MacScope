package eventstream

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNDJSONEmitsVersionedOrderedEvents(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, time.August, 24, 20, 14, 0, 0, time.FixedZone("test", -7*60*60))
	emit, err := NewNDJSON(&output, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewNDJSON returned an error: %v", err)
	}
	if err := emit(NewScanStarted("/tmp/results", false, make([]string, 0))); err != nil {
		t.Fatalf("emit scan_started: %v", err)
	}
	if err := emit(NewProgress("syft", 55, "Scanning packages")); err != nil {
		t.Fatalf("emit progress: %v", err)
	}
	if err := emit(NewScanCompleted("/tmp/results/scan.json")); err != nil {
		t.Fatalf("emit scan_completed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("event lines = %d, want 3: %q", len(lines), output.String())
	}
	for index, line := range lines {
		var envelope Envelope
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			t.Fatalf("decode event line %d: %v", index, err)
		}
		if envelope.SchemaVersion != SchemaVersion {
			t.Fatalf("event %d schema version = %q, want %q", index, envelope.SchemaVersion, SchemaVersion)
		}
		if envelope.Sequence != uint64(index+1) {
			t.Fatalf("event %d sequence = %d, want %d", index, envelope.Sequence, index+1)
		}
		if envelope.Timestamp.Location() != time.UTC {
			t.Fatalf("event %d timestamp location = %v, want UTC", index, envelope.Timestamp.Location())
		}
	}
}

func TestConstructorsCopySlices(t *testing.T) {
	excludedPaths := []string{"/Users/example/OneDrive"}
	event := NewScanStarted("/tmp/results", true, excludedPaths)
	excludedPaths[0] = "/changed"
	if event.ScanStarted.ExcludedPaths[0] != "/Users/example/OneDrive" {
		t.Fatalf("event excluded paths changed with input: %#v", event.ScanStarted.ExcludedPaths)
	}
}

func TestCommandEventsPreserveExactChunkedOutput(t *testing.T) {
	var eventOutput bytes.Buffer
	var preservedOutput bytes.Buffer
	now := time.Date(2026, time.August, 24, 20, 14, 0, 0, time.UTC)
	emit, err := NewNDJSON(&eventOutput, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewNDJSON returned an error: %v", err)
	}
	started := NewCommandStarted(
		"syft",
		"syft.filesystem-sbom",
		"/Applications/MacScope.app/Contents/Helpers/syft",
		[]string{"scan", "dir:/"},
		make([]EnvironmentVariable, 0),
		strings.Repeat("a", 64),
		128,
		true,
	)
	if err := emit(started); err != nil {
		t.Fatalf("emit command_started: %v", err)
	}
	writer, err := NewCommandOutputWriter(&preservedOutput, emit, "syft", "syft.filesystem-sbom", OutputStreamStandardOutput, true)
	if err != nil {
		t.Fatalf("NewCommandOutputWriter returned an error: %v", err)
	}
	payload := bytes.Repeat([]byte{0xff, 0x00, 'M', 'S'}, commandOutputChunkSize/4+1)
	written, err := writer.Write(payload)
	if err != nil {
		t.Fatalf("Write returned an error: %v", err)
	}
	if written != len(payload) {
		t.Fatalf("written bytes = %d, want %d", written, len(payload))
	}
	if err := emit(NewCommandCompleted("syft", "syft.filesystem-sbom", 0, "")); err != nil {
		t.Fatalf("emit command_completed: %v", err)
	}
	if !bytes.Equal(preservedOutput.Bytes(), payload) {
		t.Fatal("preserved output does not match source bytes")
	}

	lines := strings.Split(strings.TrimSpace(eventOutput.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("event lines = %d, want 4: %q", len(lines), eventOutput.String())
	}
	combined := make([]byte, 0, len(payload))
	for _, line := range lines[1:3] {
		var envelope Envelope
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			t.Fatalf("decode command output event: %v", err)
		}
		if envelope.Type != TypeCommandOutput || envelope.CommandOutput == nil {
			t.Fatalf("event = %#v, want command_output", envelope)
		}
		if !envelope.CommandOutput.MayContainPrivateData {
			t.Fatal("command output private-data marker = false, want true")
		}
		combined = append(combined, envelope.CommandOutput.Data...)
	}
	if !bytes.Equal(combined, payload) {
		t.Fatal("decoded command output chunks do not match source bytes")
	}
}

func TestEmitterRejectsInvalidEvents(t *testing.T) {
	emit := Disabled()
	invalidEvents := []Event{
		{Type: TypeProgress},
		NewProgress("", 50, "Scanning"),
		NewProgress("syft", 101, "Scanning"),
		NewCommandStarted("", "command", "/bin/test", make([]string, 0), make([]EnvironmentVariable, 0), "", 0, true),
		NewCommandStarted("syft", "command", "/bin/test", make([]string, 0), make([]EnvironmentVariable, 0), "invalid", 12, true),
		NewCommandOutput("syft", "command", "invalid", []byte("output"), true),
		NewCommandOutput("syft", "command", OutputStreamStandardOutput, make([]byte, 0), true),
		NewCommandCompleted("", "command", 0, ""),
		NewScanStarted("", false, make([]string, 0)),
		{Type: TypeScanStarted, ScanStarted: &ScanStarted{OutputDirectory: "/tmp/results", ExcludedPaths: nil}},
		NewScanCompleted(""),
		NewScanFailed("scan", " "),
	}
	for _, event := range invalidEvents {
		if err := Send(emit, event); err == nil {
			t.Fatalf("emit(%#v) returned nil error", event)
		}
	}
}

func TestDisabledCommandOutputWriterReturnsDestination(t *testing.T) {
	var destination bytes.Buffer
	writer, err := NewCommandOutputWriter(&destination, Disabled(), "syft", "syft.filesystem-sbom", OutputStreamStandardOutput, true)
	if err != nil {
		t.Fatalf("configure disabled output writer: %v", err)
	}
	if writer != &destination {
		t.Fatal("disabled output writer did not return destination directly")
	}
}
