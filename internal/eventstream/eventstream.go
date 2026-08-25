package eventstream

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const SchemaVersion = "1"

type Type string

const (
	TypeScanStarted      Type = "scan_started"
	TypeProgress         Type = "progress"
	TypeCommandStarted   Type = "command_started"
	TypeCommandOutput    Type = "command_output"
	TypeCommandCompleted Type = "command_completed"
	TypeScanCompleted    Type = "scan_completed"
	TypeScanFailed       Type = "scan_failed"
)

const commandOutputChunkSize = 24 * 1024

type OutputStream string

const (
	OutputStreamStandardOutput OutputStream = "stdout"
	OutputStreamStandardError  OutputStream = "stderr"
)

type EnvironmentVariable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ScanStarted struct {
	OutputDirectory    string   `json:"output_directory"`
	PrivilegeRequested bool     `json:"privilege_requested"`
	ExcludedPaths      []string `json:"excluded_paths"`
}

type Progress struct {
	CollectorID string `json:"collector_id"`
	Percent     int    `json:"percent"`
	Message     string `json:"message"`
}

type CommandStarted struct {
	CollectorID           string                `json:"collector_id"`
	CommandID             string                `json:"command_id"`
	Executable            string                `json:"executable"`
	Arguments             []string              `json:"arguments"`
	Environment           []EnvironmentVariable `json:"environment"`
	StandardInputSHA256   string                `json:"standard_input_sha256,omitempty"`
	StandardInputBytes    int                   `json:"standard_input_bytes"`
	MayContainPrivateData bool                  `json:"may_contain_private_data"`
}

type CommandOutput struct {
	CollectorID           string       `json:"collector_id"`
	CommandID             string       `json:"command_id"`
	Stream                OutputStream `json:"stream"`
	Data                  []byte       `json:"data_base64"`
	MayContainPrivateData bool         `json:"may_contain_private_data"`
}

type CommandCompleted struct {
	CollectorID    string `json:"collector_id"`
	CommandID      string `json:"command_id"`
	ExitCode       int    `json:"exit_code"`
	ExecutionError string `json:"execution_error,omitempty"`
}

type ScanCompleted struct {
	ReportPath string `json:"report_path"`
}

type ScanFailed struct {
	ErrorType string `json:"error_type"`
	Message   string `json:"message"`
}

type Event struct {
	Type             Type              `json:"type"`
	ScanStarted      *ScanStarted      `json:"scan_started,omitempty"`
	Progress         *Progress         `json:"progress,omitempty"`
	CommandStarted   *CommandStarted   `json:"command_started,omitempty"`
	CommandOutput    *CommandOutput    `json:"command_output,omitempty"`
	CommandCompleted *CommandCompleted `json:"command_completed,omitempty"`
	ScanCompleted    *ScanCompleted    `json:"scan_completed,omitempty"`
	ScanFailed       *ScanFailed       `json:"scan_failed,omitempty"`
}

type Envelope struct {
	SchemaVersion string    `json:"schema_version"`
	Sequence      uint64    `json:"sequence"`
	Timestamp     time.Time `json:"timestamp"`
	Event
}

type Emit func(Event) error

func Disabled() Emit {
	return nil
}

func Send(emit Emit, event Event) error {
	if err := validateEvent(event); err != nil {
		return err
	}
	if emit == nil {
		return nil
	}
	return emit(event)
}

func NewNDJSON(writer io.Writer, now func() time.Time) (Emit, error) {
	if writer == nil {
		return nil, fmt.Errorf("configure JSON event stream: writer must not be nil")
	}
	if now == nil {
		return nil, fmt.Errorf("configure JSON event stream: clock must not be nil")
	}

	var mutex sync.Mutex
	var sequence uint64
	emit := func(event Event) error {
		if err := validateEvent(event); err != nil {
			return err
		}
		mutex.Lock()
		defer mutex.Unlock()
		sequence++
		timestamp := now().UTC()
		if timestamp.IsZero() {
			return fmt.Errorf("encode JSON event sequence %d type %q: timestamp must not be zero", sequence, event.Type)
		}
		envelope := Envelope{
			SchemaVersion: SchemaVersion,
			Sequence:      sequence,
			Timestamp:     timestamp,
			Event:         event,
		}
		encoded, err := json.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("encode JSON event sequence %d type %q: %w", sequence, event.Type, err)
		}
		encoded = append(encoded, '\n')
		written, err := writer.Write(encoded)
		if err != nil {
			return fmt.Errorf("write JSON event sequence %d type %q: %w", sequence, event.Type, err)
		}
		if written != len(encoded) {
			return fmt.Errorf("write JSON event sequence %d type %q: wrote %d of %d bytes: %w", sequence, event.Type, written, len(encoded), io.ErrShortWrite)
		}
		return nil
	}
	return emit, nil
}

func NewScanStarted(outputDirectory string, privilegeRequested bool, excludedPaths []string) Event {
	copiedExcludedPaths := make([]string, len(excludedPaths))
	copy(copiedExcludedPaths, excludedPaths)
	return Event{
		Type: TypeScanStarted,
		ScanStarted: &ScanStarted{
			OutputDirectory:    outputDirectory,
			PrivilegeRequested: privilegeRequested,
			ExcludedPaths:      copiedExcludedPaths,
		},
	}
}

func NewProgress(collectorID string, percent int, message string) Event {
	return Event{
		Type: TypeProgress,
		Progress: &Progress{
			CollectorID: collectorID,
			Percent:     percent,
			Message:     message,
		},
	}
}

func NewCommandStarted(collectorID string, commandID string, executable string, arguments []string, environment []EnvironmentVariable, standardInputSHA256 string, standardInputBytes int, mayContainPrivateData bool) Event {
	copiedArguments := make([]string, len(arguments))
	copy(copiedArguments, arguments)
	copiedEnvironment := make([]EnvironmentVariable, len(environment))
	copy(copiedEnvironment, environment)
	return Event{
		Type: TypeCommandStarted,
		CommandStarted: &CommandStarted{
			CollectorID:           collectorID,
			CommandID:             commandID,
			Executable:            executable,
			Arguments:             copiedArguments,
			Environment:           copiedEnvironment,
			StandardInputSHA256:   standardInputSHA256,
			StandardInputBytes:    standardInputBytes,
			MayContainPrivateData: mayContainPrivateData,
		},
	}
}

func NewCommandOutput(collectorID string, commandID string, stream OutputStream, data []byte, mayContainPrivateData bool) Event {
	copiedData := make([]byte, len(data))
	copy(copiedData, data)
	return Event{
		Type: TypeCommandOutput,
		CommandOutput: &CommandOutput{
			CollectorID:           collectorID,
			CommandID:             commandID,
			Stream:                stream,
			Data:                  copiedData,
			MayContainPrivateData: mayContainPrivateData,
		},
	}
}

func NewCommandCompleted(collectorID string, commandID string, exitCode int, executionError string) Event {
	return Event{
		Type: TypeCommandCompleted,
		CommandCompleted: &CommandCompleted{
			CollectorID:    collectorID,
			CommandID:      commandID,
			ExitCode:       exitCode,
			ExecutionError: executionError,
		},
	}
}

func NewCommandOutputWriter(destination io.Writer, emit Emit, collectorID string, commandID string, stream OutputStream, mayContainPrivateData bool) (io.Writer, error) {
	if destination == nil {
		return nil, fmt.Errorf("configure command output writer: destination must not be nil")
	}
	probe := NewCommandOutput(collectorID, commandID, stream, []byte{0}, mayContainPrivateData)
	if err := validateEvent(probe); err != nil {
		return nil, fmt.Errorf("configure command output writer: %w", err)
	}
	if emit == nil {
		return destination, nil
	}
	return commandOutputWriter{
		destination:           destination,
		emit:                  emit,
		collectorID:           collectorID,
		commandID:             commandID,
		stream:                stream,
		mayContainPrivateData: mayContainPrivateData,
	}, nil
}

func NewScanCompleted(reportPath string) Event {
	return Event{
		Type:          TypeScanCompleted,
		ScanCompleted: &ScanCompleted{ReportPath: reportPath},
	}
}

func NewScanFailed(errorType string, message string) Event {
	return Event{
		Type: TypeScanFailed,
		ScanFailed: &ScanFailed{
			ErrorType: errorType,
			Message:   message,
		},
	}
}

func validateEvent(event Event) error {
	payloadCount := 0
	if event.ScanStarted != nil {
		payloadCount++
	}
	if event.Progress != nil {
		payloadCount++
	}
	if event.CommandStarted != nil {
		payloadCount++
	}
	if event.CommandOutput != nil {
		payloadCount++
	}
	if event.CommandCompleted != nil {
		payloadCount++
	}
	if event.ScanCompleted != nil {
		payloadCount++
	}
	if event.ScanFailed != nil {
		payloadCount++
	}
	if payloadCount != 1 {
		return fmt.Errorf("validate JSON event type %q: exactly one payload is required; received %d", event.Type, payloadCount)
	}

	switch event.Type {
	case TypeScanStarted:
		if event.ScanStarted == nil {
			return payloadMismatchError(event.Type)
		}
		if strings.TrimSpace(event.ScanStarted.OutputDirectory) == "" {
			return fmt.Errorf("validate JSON event type %q: output directory must not be empty", event.Type)
		}
		if event.ScanStarted.ExcludedPaths == nil {
			return fmt.Errorf("validate JSON event type %q: excluded paths must not be null", event.Type)
		}
	case TypeProgress:
		if event.Progress == nil {
			return payloadMismatchError(event.Type)
		}
		if strings.TrimSpace(event.Progress.CollectorID) == "" {
			return fmt.Errorf("validate JSON event type %q: collector ID must not be empty", event.Type)
		}
		if event.Progress.Percent < 0 || event.Progress.Percent > 100 {
			return fmt.Errorf("validate JSON event type %q: percent %d is outside 0 through 100", event.Type, event.Progress.Percent)
		}
		if strings.TrimSpace(event.Progress.Message) == "" {
			return fmt.Errorf("validate JSON event type %q: message must not be empty", event.Type)
		}
	case TypeCommandStarted:
		if event.CommandStarted == nil {
			return payloadMismatchError(event.Type)
		}
		if err := validateCommandIdentity(event.Type, event.CommandStarted.CollectorID, event.CommandStarted.CommandID); err != nil {
			return err
		}
		if strings.TrimSpace(event.CommandStarted.Executable) == "" {
			return fmt.Errorf("validate JSON event type %q: executable must not be empty", event.Type)
		}
		if event.CommandStarted.Arguments == nil {
			return fmt.Errorf("validate JSON event type %q: arguments must not be null", event.Type)
		}
		if event.CommandStarted.Environment == nil {
			return fmt.Errorf("validate JSON event type %q: environment must not be null", event.Type)
		}
		if event.CommandStarted.StandardInputBytes < 0 {
			return fmt.Errorf("validate JSON event type %q: standard input bytes must not be negative", event.Type)
		}
		if event.CommandStarted.StandardInputBytes == 0 && event.CommandStarted.StandardInputSHA256 != "" {
			return fmt.Errorf("validate JSON event type %q: standard input SHA-256 requires nonzero input bytes", event.Type)
		}
		if event.CommandStarted.StandardInputBytes > 0 && !isLowercaseSHA256(event.CommandStarted.StandardInputSHA256) {
			return fmt.Errorf("validate JSON event type %q: standard input SHA-256 must contain 64 lowercase hexadecimal characters", event.Type)
		}
		for index, variable := range event.CommandStarted.Environment {
			if strings.TrimSpace(variable.Name) == "" {
				return fmt.Errorf("validate JSON event type %q: environment variable %d name must not be empty", event.Type, index)
			}
			if strings.Contains(variable.Name, "=") {
				return fmt.Errorf("validate JSON event type %q: environment variable %d name must not contain '='", event.Type, index)
			}
		}
	case TypeCommandOutput:
		if event.CommandOutput == nil {
			return payloadMismatchError(event.Type)
		}
		if err := validateCommandIdentity(event.Type, event.CommandOutput.CollectorID, event.CommandOutput.CommandID); err != nil {
			return err
		}
		if event.CommandOutput.Stream != OutputStreamStandardOutput && event.CommandOutput.Stream != OutputStreamStandardError {
			return fmt.Errorf("validate JSON event type %q: unsupported output stream %q", event.Type, event.CommandOutput.Stream)
		}
		if len(event.CommandOutput.Data) == 0 {
			return fmt.Errorf("validate JSON event type %q: output data must not be empty", event.Type)
		}
	case TypeCommandCompleted:
		if event.CommandCompleted == nil {
			return payloadMismatchError(event.Type)
		}
		if err := validateCommandIdentity(event.Type, event.CommandCompleted.CollectorID, event.CommandCompleted.CommandID); err != nil {
			return err
		}
	case TypeScanCompleted:
		if event.ScanCompleted == nil {
			return payloadMismatchError(event.Type)
		}
		if strings.TrimSpace(event.ScanCompleted.ReportPath) == "" {
			return fmt.Errorf("validate JSON event type %q: report path must not be empty", event.Type)
		}
	case TypeScanFailed:
		if event.ScanFailed == nil {
			return payloadMismatchError(event.Type)
		}
		if strings.TrimSpace(event.ScanFailed.ErrorType) == "" {
			return fmt.Errorf("validate JSON event type %q: error type must not be empty", event.Type)
		}
		if strings.TrimSpace(event.ScanFailed.Message) == "" {
			return fmt.Errorf("validate JSON event type %q: message must not be empty", event.Type)
		}
	default:
		return fmt.Errorf("validate JSON event: unsupported type %q", event.Type)
	}
	return nil
}

func payloadMismatchError(eventType Type) error {
	return fmt.Errorf("validate JSON event type %q: payload does not match type", eventType)
}

func validateCommandIdentity(eventType Type, collectorID string, commandID string) error {
	if strings.TrimSpace(collectorID) == "" {
		return fmt.Errorf("validate JSON event type %q: collector ID must not be empty", eventType)
	}
	if strings.TrimSpace(commandID) == "" {
		return fmt.Errorf("validate JSON event type %q: command ID must not be empty", eventType)
	}
	return nil
}

func isLowercaseSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

type commandOutputWriter struct {
	destination           io.Writer
	emit                  Emit
	collectorID           string
	commandID             string
	stream                OutputStream
	mayContainPrivateData bool
}

func (writer commandOutputWriter) Write(content []byte) (int, error) {
	written, destinationError := writer.destination.Write(content)
	for offset := 0; offset < written; offset += commandOutputChunkSize {
		end := offset + commandOutputChunkSize
		if end > written {
			end = written
		}
		if err := Send(writer.emit, NewCommandOutput(writer.collectorID, writer.commandID, writer.stream, content[offset:end], writer.mayContainPrivateData)); err != nil {
			return written, fmt.Errorf("emit %s output for command %q: %w", writer.stream, writer.commandID, err)
		}
	}
	if destinationError != nil {
		return written, fmt.Errorf("preserve %s output for command %q: %w", writer.stream, writer.commandID, destinationError)
	}
	if written != len(content) {
		return written, fmt.Errorf("preserve %s output for command %q: wrote %d of %d bytes: %w", writer.stream, writer.commandID, written, len(content), io.ErrShortWrite)
	}
	return written, nil
}
