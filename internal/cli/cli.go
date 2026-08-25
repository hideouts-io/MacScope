package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

type CommandKind string

const (
	CommandHelp                CommandKind = "help"
	CommandVersion             CommandKind = "version"
	CommandScan                CommandKind = "scan"
	CommandReport              CommandKind = "report"
	CommandPrivilegedCollector CommandKind = "internal-collect-privileged"
)

type ScanCommand struct {
	OutputDirectory    string
	PrivilegeRequested bool
	ExcludedPaths      []string
	EventsJSON         bool
}

type ReportCommand struct {
	InputPath  string
	OutputPath string
}

type Command struct {
	Kind   CommandKind
	Scan   ScanCommand
	Report ReportCommand
}

type UsageError struct {
	Message string
}

type repeatedStringFlag []string

func (values *repeatedStringFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *repeatedStringFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("path must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func (err UsageError) Error() string {
	return err.Message
}

func Parse(arguments []string) (Command, error) {
	if len(arguments) == 0 {
		return Command{}, UsageError{Message: "a command is required"}
	}

	switch arguments[0] {
	case "help", "--help", "-h":
		if len(arguments) != 1 {
			return Command{}, UsageError{Message: "help does not accept arguments"}
		}
		return Command{Kind: CommandHelp}, nil
	case "version":
		if len(arguments) != 1 {
			return Command{}, UsageError{Message: "version does not accept arguments"}
		}
		return Command{Kind: CommandVersion}, nil
	case "scan":
		return parseScan(arguments[1:])
	case "report":
		return parseReport(arguments[1:])
	case "internal-collect-privileged":
		if len(arguments) != 1 {
			return Command{}, UsageError{Message: "internal privileged collector does not accept arguments"}
		}
		return Command{Kind: CommandPrivilegedCollector}, nil
	default:
		return Command{}, UsageError{Message: fmt.Sprintf("unknown command %q", arguments[0])}
	}
}

func parseReport(arguments []string) (Command, error) {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "", "validated scan JSON path")
	outputPath := flags.String("output", "", "offline HTML report path")

	if err := flags.Parse(arguments); err != nil {
		return Command{}, UsageError{Message: fmt.Sprintf("parse report arguments: %v", err)}
	}
	if flags.NArg() != 0 {
		return Command{}, UsageError{Message: fmt.Sprintf("unexpected report argument %q", flags.Arg(0))}
	}
	if *inputPath == "" {
		return Command{}, UsageError{Message: "report requires --input <scan.json>"}
	}
	if *outputPath == "" {
		return Command{}, UsageError{Message: "report requires --output <report.html>"}
	}

	return Command{
		Kind: CommandReport,
		Report: ReportCommand{
			InputPath:  *inputPath,
			OutputPath: *outputPath,
		},
	}, nil
}

func parseScan(arguments []string) (Command, error) {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	outputDirectory := flags.String("output", "", "directory for scan artifacts")
	privilegeRequested := flags.Bool("privileged", false, "run narrow read-only collectors through sudo")
	eventsJSON := flags.Bool("events-json", false, "write versioned NDJSON scan events to stdout")
	excludedPaths := make(repeatedStringFlag, 0)
	flags.Var(&excludedPaths, "exclude", "absolute file or directory to exclude from Syft; repeat for multiple paths")

	if err := flags.Parse(arguments); err != nil {
		return Command{}, UsageError{Message: fmt.Sprintf("parse scan arguments: %v", err)}
	}
	if flags.NArg() != 0 {
		return Command{}, UsageError{Message: fmt.Sprintf("unexpected scan argument %q", flags.Arg(0))}
	}
	if *outputDirectory == "" {
		return Command{}, UsageError{Message: "scan requires --output <directory>"}
	}

	return Command{
		Kind: CommandScan,
		Scan: ScanCommand{
			OutputDirectory:    *outputDirectory,
			PrivilegeRequested: *privilegeRequested,
			ExcludedPaths:      append([]string(nil), excludedPaths...),
			EventsJSON:         *eventsJSON,
		},
	}, nil
}

func Usage() string {
	return "Usage:\n  macscope scan --output <directory> [--privileged] [--events-json] [--exclude <absolute-path>]...\n  macscope report --input <scan.json> --output <report.html>\n  macscope version\n  macscope help"
}

func IsUsageError(err error) bool {
	var usageError UsageError
	return errors.As(err, &usageError)
}
