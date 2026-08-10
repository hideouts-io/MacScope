package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"macscope/internal/banner"
	"macscope/internal/cli"
	"macscope/internal/privilege"
	"macscope/internal/report"
	"macscope/internal/scan"
	"macscope/internal/version"
)

func main() {
	displayBanner, err := banner.ShouldDisplay(os.Stdout, os.Getenv("MACSCOPE_NO_BANNER"))
	if err != nil {
		writeError(os.Stderr, "banner", err)
		os.Exit(1)
	}
	if displayBanner {
		var err error
		if banner.ColorEnabled(os.Getenv("NO_COLOR"), os.Getenv("TERM")) {
			err = banner.RenderAnimated(os.Stdout, time.Sleep, rand.Reader, version.BuildSummary(), 35*time.Millisecond)
		} else {
			err = banner.RenderPlain(os.Stdout, rand.Reader, version.BuildSummary())
		}
		if err != nil {
			writeError(os.Stderr, "banner", err)
			os.Exit(1)
		}
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout io.Writer, stderr io.Writer) int {
	command, err := cli.Parse(arguments)
	if err != nil {
		writeError(stderr, "usage", err)
		fmt.Fprintln(stderr, cli.Usage())
		return 2
	}

	switch command.Kind {
	case cli.CommandHelp:
		fmt.Fprintln(stdout, cli.Usage())
		return 0
	case cli.CommandVersion:
		fmt.Fprintln(stdout, version.Current)
		return 0
	case cli.CommandPrivilegedCollector:
		if err := privilege.WriteInternalResult(os.Geteuid(), stdout); err != nil {
			writeError(stderr, "privilege", err)
			return 1
		}
		return 0
	case cli.CommandScan:
		executable, err := os.Executable()
		if err != nil {
			writeError(stderr, "runtime", fmt.Errorf("resolve MacScope executable path: %w", err))
			return 1
		}

		result, err := scan.Run(command.Scan, executable, os.Geteuid(), os.Stdin, stderr)
		if err != nil {
			writeError(stderr, "scan", err)
			return 1
		}
		fmt.Fprintf(stdout, "scan report: %s\n", result.ReportPath)
		return 0
	case cli.CommandReport:
		result, err := report.Generate(command.Report.InputPath, command.Report.OutputPath)
		if err != nil {
			writeError(stderr, "report", err)
			return 1
		}
		fmt.Fprintf(stdout, "HTML report: %s\n", result.OutputPath)
		return 0
	default:
		writeError(stderr, "runtime", fmt.Errorf("unsupported command kind %q", command.Kind))
		return 1
	}
}

func writeError(writer io.Writer, errorType string, err error) {
	payload := struct {
		Level   string `json:"level"`
		Type    string `json:"type"`
		Message string `json:"message"`
	}{
		Level:   "error",
		Type:    errorType,
		Message: err.Error(),
	}

	encoded, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		fmt.Fprintf(writer, "error: encode structured error: %v\n", marshalErr)
		return
	}
	_, _ = fmt.Fprintln(writer, string(encoded))
}
