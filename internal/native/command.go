package native

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
	"unicode/utf8"

	"macscope/internal/model"
)

const probeTimeout = 20 * time.Second

type ProbeResult struct {
	ID             string    `json:"id"`
	Executable     string    `json:"executable"`
	Arguments      []string  `json:"arguments"`
	Privileged     bool      `json:"privileged"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	ExitCode       int       `json:"exit_code"`
	StandardOutput []byte    `json:"standard_output_base64"`
	StandardError  []byte    `json:"standard_error_base64"`
	ExecutionError string    `json:"execution_error,omitempty"`
}

type probeSpec struct {
	ID         string
	Area       model.CoverageArea
	Target     string
	Executable string
	Arguments  []string
	Privileged bool
	Parser     probeParser
	Rule       *findingRule
	Component  componentIdentity
}

type probeParser func(result ProbeResult) (assessment, error)

type ProbeExecutionError struct {
	ProbeID string
	Message string
}

func (err ProbeExecutionError) Error() string {
	return fmt.Sprintf("native probe %q failed: %s", err.ProbeID, err.Message)
}

func runProbe(parentContext context.Context, spec probeSpec) ProbeResult {
	probeContext, cancel := context.WithTimeout(parentContext, probeTimeout)
	defer cancel()

	startedAt := time.Now().UTC()
	command := exec.CommandContext(probeContext, spec.Executable, spec.Arguments...)
	var standardOutput bytes.Buffer
	var standardError bytes.Buffer
	command.Stdout = &standardOutput
	command.Stderr = &standardError

	runError := command.Run()
	completedAt := time.Now().UTC()
	exitCode := 0
	executionError := ""
	if runError != nil {
		executionError = runError.Error()
		exitCode = -1
		var exitError *exec.ExitError
		if errors.As(runError, &exitError) {
			exitCode = exitError.ExitCode()
		}
	}
	if probeContext.Err() != nil {
		executionError = fmt.Sprintf("probe exceeded timeout %s: %v", probeTimeout, probeContext.Err())
	}

	stdoutBytes := standardOutput.Bytes()
	stderrBytes := standardError.Bytes()
	if !utf8.Valid(stdoutBytes) {
		executionError = appendExecutionError(executionError, "standard output is not valid UTF-8")
	}
	if !utf8.Valid(stderrBytes) {
		executionError = appendExecutionError(executionError, "standard error is not valid UTF-8")
	}

	return ProbeResult{
		ID:             spec.ID,
		Executable:     spec.Executable,
		Arguments:      append([]string(nil), spec.Arguments...),
		Privileged:     spec.Privileged,
		StartedAt:      startedAt,
		CompletedAt:    completedAt,
		ExitCode:       exitCode,
		StandardOutput: append([]byte(nil), stdoutBytes...),
		StandardError:  append([]byte(nil), stderrBytes...),
		ExecutionError: executionError,
	}
}

func appendExecutionError(existing string, addition string) string {
	if existing == "" {
		return addition
	}
	return existing + "; " + addition
}
