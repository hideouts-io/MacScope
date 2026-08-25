package progress

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestFormatLineShowsBarPercentageMessageAndElapsedTime(t *testing.T) {
	line, err := formatLine(Event{CollectorID: "syft", Percent: 50, Message: "Scanning installed software"}, 65*time.Second, 2, 10)
	if err != nil {
		t.Fatalf("formatLine returned an error: %v", err)
	}
	want := "[█████░░░░░]  50% -  Scanning installed software  elapsed 01:05"
	if line != want {
		t.Fatalf("FormatLine = %q, want %q", line, want)
	}
}

func TestFormatLineRejectsInvalidWidthAndElapsedTime(t *testing.T) {
	event := Event{CollectorID: "syft", Percent: 50, Message: "Scanning installed software"}
	if _, err := formatLine(event, time.Second, 0, 0); err == nil {
		t.Fatal("formatLine accepted zero bar width")
	}
	if _, err := formatLine(event, -time.Second, 0, 10); err == nil {
		t.Fatal("formatLine accepted negative elapsed time")
	}
}

func TestNewTerminalReportsMessagesAndCloses(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, time.August, 10, 1, 2, 3, 0, time.UTC)
	tracker, err := NewTerminal(&output, time.Hour, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewTerminal returned an error: %v", err)
	}
	if err := tracker.Report(Event{CollectorID: "macscope", Percent: 25, Message: "Collecting native controls"}); err != nil {
		t.Fatalf("Report returned an error: %v", err)
	}
	if _, err := fmt.Fprintln(tracker.Messages, `{"level":"warning"}`); err != nil {
		t.Fatalf("write progress-aware message: %v", err)
	}
	if err := tracker.Close(); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}
	content := output.String()
	for _, wanted := range []string{"25%", "Collecting native controls", `{"level":"warning"}`, "\x1b[91m"} {
		if !strings.Contains(content, wanted) {
			t.Fatalf("terminal progress output does not contain %q: %q", wanted, content)
		}
	}
	if !strings.HasSuffix(content, "\x1b[0m\n") {
		t.Fatalf("terminal progress output does not end with a reset and newline: %q", content)
	}
}

func TestNewPlainWritesOneLinePerEventWithoutANSI(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, time.August, 10, 1, 2, 3, 0, time.UTC)
	tracker, err := NewPlain(&output, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewPlain returned an error: %v", err)
	}
	if err := tracker.Report(Event{CollectorID: "macscope", Percent: 10, Message: "Preparing"}); err != nil {
		t.Fatalf("Report returned an error: %v", err)
	}
	if strings.Contains(output.String(), "\x1b[") {
		t.Fatalf("plain progress contains ANSI escapes: %q", output.String())
	}
	if !strings.Contains(output.String(), "10%") || !strings.Contains(output.String(), "Preparing") {
		t.Fatalf("plain progress does not contain event details: %q", output.String())
	}
}

func TestReporterRejectsInvalidEvents(t *testing.T) {
	tracker := Disabled(&bytes.Buffer{})
	for _, event := range []Event{
		{CollectorID: "", Percent: 50, Message: "invalid"},
		{CollectorID: "macscope", Percent: -1, Message: "invalid"},
		{CollectorID: "macscope", Percent: 101, Message: "invalid"},
		{CollectorID: "macscope", Percent: 50, Message: " "},
	} {
		if err := tracker.Report(event); err == nil {
			t.Fatalf("Report(%#v) returned nil error", event)
		}
	}
}
