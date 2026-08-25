package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"macscope/internal/banner"
	"macscope/internal/cli"
	"macscope/internal/eventstream"
	"macscope/internal/privilege"
	"macscope/internal/progress"
	"macscope/internal/report"
	"macscope/internal/scan"
	"macscope/internal/version"
)

func main() {
	parentContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	arguments := os.Args[1:]
	jsonEvents := jsonEventsRequested(arguments)
	displayBanner, err := banner.ShouldDisplay(os.Stdout, os.Getenv("MACSCOPE_NO_BANNER"))
	if err != nil {
		writeError(os.Stderr, "banner", err)
		os.Exit(1)
	}
	if displayBanner && !jsonEvents {
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
	eventEmitter := eventstream.Disabled()
	if jsonEvents {
		eventEmitter, err = eventstream.NewNDJSON(os.Stdout, time.Now)
		if err != nil {
			writeError(os.Stderr, "events", err)
			os.Exit(1)
		}
	}
	scanContext, cancelScan := context.WithCancel(parentContext)
	defer cancelScan()
	if jsonEvents {
		streamEmitter := eventEmitter
		eventEmitter = func(event eventstream.Event) error {
			if err := streamEmitter(event); err != nil {
				cancelScan()
				return err
			}
			return nil
		}
	}
	progressTracker := progress.Disabled(os.Stderr)
	if len(arguments) > 0 && arguments[0] == "scan" && !jsonEvents {
		displayProgress, err := progress.ShouldDisplay(os.Stderr, os.Getenv("MACSCOPE_NO_PROGRESS"))
		if err != nil {
			writeError(os.Stderr, "progress", err)
			os.Exit(1)
		}
		if displayProgress {
			if progress.ColorEnabled(os.Getenv("NO_COLOR"), os.Getenv("TERM")) {
				progressTracker, err = progress.NewTerminal(os.Stderr, 120*time.Millisecond, time.Now)
			} else {
				progressTracker, err = progress.NewPlain(os.Stderr, time.Now)
			}
			if err != nil {
				writeError(os.Stderr, "progress", err)
				os.Exit(1)
			}
		}
	}
	if jsonEvents {
		baseReporter := progressTracker.Report
		progressTracker.Report = func(event progress.Event) error {
			if err := baseReporter(event); err != nil {
				return err
			}
			return eventstream.Send(eventEmitter, eventstream.NewProgress(event.CollectorID, event.Percent, event.Message))
		}
	}
	exitCode := run(scanContext, arguments, os.Stdout, os.Stderr, progressTracker, eventEmitter)
	if err := progressTracker.Close(); err != nil {
		writeError(os.Stderr, "progress", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}

func run(parentContext context.Context, arguments []string, stdout io.Writer, stderr io.Writer, progressTracker progress.Tracker, eventEmitter eventstream.Emit) int {
	if parentContext == nil {
		writeError(stderr, "runtime", fmt.Errorf("run MacScope: context must not be nil"))
		return 1
	}
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
		if err := privilege.WriteInternalResult(parentContext, os.Geteuid(), stdout, eventEmitter); err != nil {
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
		if err := eventstream.Send(eventEmitter, eventstream.NewScanStarted(command.Scan.OutputDirectory, command.Scan.PrivilegeRequested, command.Scan.ExcludedPaths)); err != nil {
			writeError(stderr, "events", err)
			return 1
		}

		result, scanErr := scan.Run(parentContext, command.Scan, executable, os.Geteuid(), os.Stdin, stderr, progressTracker, eventEmitter)
		progressErr := progressTracker.Close()
		if scanErr != nil {
			if progressErr != nil {
				scanErr = errors.Join(scanErr, progressErr)
			}
			errorType := "scan"
			exitCode := 1
			if errors.Is(scanErr, context.Canceled) {
				errorType = "canceled"
				exitCode = 130
			}
			if eventErr := eventstream.Send(eventEmitter, eventstream.NewScanFailed(errorType, scanErr.Error())); eventErr != nil {
				scanErr = errors.Join(scanErr, eventErr)
			}
			writeError(stderr, "scan", scanErr)
			return exitCode
		}
		if progressErr != nil {
			if eventErr := eventstream.Send(eventEmitter, eventstream.NewScanFailed("progress", progressErr.Error())); eventErr != nil {
				progressErr = errors.Join(progressErr, eventErr)
			}
			writeError(stderr, "progress", progressErr)
			return 1
		}
		if err := eventstream.Send(eventEmitter, eventstream.NewScanCompleted(result.ReportPath)); err != nil {
			writeError(stderr, "events", err)
			return 1
		}
		if !command.Scan.EventsJSON {
			fmt.Fprintf(stdout, "scan report: %s\n", result.ReportPath)
		}
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

func jsonEventsRequested(arguments []string) bool {
	command, err := cli.Parse(arguments)
	if err != nil || command.Kind != cli.CommandScan {
		return false
	}
	return command.Scan.EventsJSON
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
