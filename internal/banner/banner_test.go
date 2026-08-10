package banner

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRenderAnimatedSelectsDesignAndCyclesColors(t *testing.T) {
	var output bytes.Buffer
	delays := make([]time.Duration, 0)
	err := RenderAnimated(&output, func(delay time.Duration) {
		delays = append(delays, delay)
	}, bytes.NewReader([]byte{1}), "version 1.2.3 | build abc123", 5*time.Millisecond)
	if err != nil {
		t.Fatalf("RenderAnimated returned an error: %v", err)
	}
	rendered := output.String()
	if !strings.Contains(rendered, "|  \\/  | __ _") {
		t.Fatalf("rendered banner does not contain selected design: %q", rendered)
	}
	if !strings.Contains(rendered, "version 1.2.3 | build abc123") {
		t.Fatalf("rendered banner does not contain version/build summary")
	}
	for _, color := range animationColors {
		if !strings.Contains(rendered, color) {
			t.Fatalf("rendered banner does not contain animation color %q", color)
		}
	}
	if len(delays) != len(animationColors)-1 {
		t.Fatalf("animation delay count = %d, want %d", len(delays), len(animationColors)-1)
	}
	for _, delay := range delays {
		if delay != 5*time.Millisecond {
			t.Fatalf("animation delay = %s, want 5ms", delay)
		}
	}
}

func TestRenderPlainContainsNoANSISequences(t *testing.T) {
	var output bytes.Buffer
	if err := RenderPlain(&output, bytes.NewReader([]byte{2}), "version 1.2.3 | build local"); err != nil {
		t.Fatalf("RenderPlain returned an error: %v", err)
	}
	rendered := output.String()
	if strings.Contains(rendered, "\x1b[") {
		t.Fatalf("plain banner contains ANSI escape sequence: %q", rendered)
	}
	if !strings.Contains(rendered, "/  |/  /___") || !strings.Contains(rendered, "version 1.2.3 | build local") {
		t.Fatalf("plain banner is missing selected design or build summary: %q", rendered)
	}
}

func TestSelectDesignReturnsRandomSourceError(t *testing.T) {
	_, err := selectDesign(bytes.NewReader(nil))
	if err == nil || !errors.Is(err, io.EOF) {
		t.Fatalf("selectDesign error = %v, want explicit random-source error", err)
	}
}

func TestShouldDisplayAndColorEnabled(t *testing.T) {
	display, err := ShouldDisplay(os.Stdout, "1")
	if err != nil {
		t.Fatalf("ShouldDisplay disabled returned an error: %v", err)
	}
	if display {
		t.Fatal("ShouldDisplay disabled = true, want false")
	}
	file, err := os.CreateTemp(t.TempDir(), "banner-output-")
	if err != nil {
		t.Fatalf("create non-terminal output: %v", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("close non-terminal output: %v", closeErr)
		}
	}()
	display, err = ShouldDisplay(file, "")
	if err != nil {
		t.Fatalf("ShouldDisplay file returned an error: %v", err)
	}
	if display {
		t.Fatal("ShouldDisplay regular file = true, want false")
	}
	if !ColorEnabled("", "xterm-256color") || ColorEnabled("1", "xterm-256color") || ColorEnabled("", "dumb") {
		t.Fatal("ColorEnabled did not honor NO_COLOR or TERM=dumb")
	}
}
