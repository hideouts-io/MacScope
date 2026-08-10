package osquery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	ToolID                 = "osquery"
	ExpectedVersion        = "5.21.0"
	ExpectedExecutableHash = "2cd76aed19a9fb0da18ee11f36272b9632c0dde71509b746f7142b31a703e9f5"
	OriginURL              = "https://github.com/osquery/osquery/releases/tag/5.21.0"
)

type ClientConfig struct {
	ExecutablePath  string
	ExpectedVersion string
	ExpectedSHA256  string
	QueryTimeout    time.Duration
}

type Client struct {
	config ClientConfig
}

type QueryResult struct {
	ID             string
	Arguments      []string
	StartedAt      time.Time
	CompletedAt    time.Time
	ExitCode       int
	StandardOutput []byte
	StandardError  []byte
	ExecutionError string
}

type Verification struct {
	Version string
	SHA256  string
	Result  QueryResult
}

type VerificationError struct {
	Path  string
	Cause error
}

func (err VerificationError) Error() string {
	return fmt.Sprintf("verify pinned osquery executable %q: %v", err.Path, err.Cause)
}

func (err VerificationError) Unwrap() error {
	return err.Cause
}

func NewClient(config ClientConfig) (Client, error) {
	if strings.TrimSpace(config.ExecutablePath) == "" {
		return Client{}, fmt.Errorf("osquery executable path must not be empty")
	}
	if strings.TrimSpace(config.ExpectedVersion) == "" {
		return Client{}, fmt.Errorf("osquery expected version must not be empty")
	}
	if len(config.ExpectedSHA256) != 64 {
		return Client{}, fmt.Errorf("osquery expected SHA-256 %q must contain 64 lowercase hexadecimal characters", config.ExpectedSHA256)
	}
	for _, character := range config.ExpectedSHA256 {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return Client{}, fmt.Errorf("osquery expected SHA-256 %q must contain 64 lowercase hexadecimal characters", config.ExpectedSHA256)
		}
	}
	if config.QueryTimeout <= 0 {
		return Client{}, fmt.Errorf("osquery query timeout must be positive; received %s", config.QueryTimeout)
	}
	return Client{config: config}, nil
}

func (client Client) Verify(parentContext context.Context) (Verification, error) {
	fileInfo, err := os.Stat(client.config.ExecutablePath)
	if err != nil {
		return Verification{}, VerificationError{Path: client.config.ExecutablePath, Cause: fmt.Errorf("stat executable: %w", err)}
	}
	if !fileInfo.Mode().IsRegular() {
		return Verification{}, VerificationError{Path: client.config.ExecutablePath, Cause: fmt.Errorf("path is not a regular file")}
	}
	if fileInfo.Mode().Perm()&0o111 == 0 {
		return Verification{}, VerificationError{Path: client.config.ExecutablePath, Cause: fmt.Errorf("file has no executable permission bits")}
	}
	digest, err := hashFile(client.config.ExecutablePath)
	if err != nil {
		return Verification{}, VerificationError{Path: client.config.ExecutablePath, Cause: err}
	}
	if digest != client.config.ExpectedSHA256 {
		return Verification{}, VerificationError{Path: client.config.ExecutablePath, Cause: fmt.Errorf("SHA-256 mismatch: expected %s, calculated %s", client.config.ExpectedSHA256, digest)}
	}
	result := client.execute(parentContext, "version", []string{"--version"})
	if result.ExecutionError != "" || result.ExitCode != 0 {
		return Verification{SHA256: digest, Result: result}, VerificationError{Path: client.config.ExecutablePath, Cause: fmt.Errorf("version command failed: exit_code=%d execution_error=%q stderr=%q", result.ExitCode, result.ExecutionError, string(result.StandardError))}
	}
	version, err := parseVersion(result.StandardOutput)
	if err != nil {
		return Verification{SHA256: digest, Result: result}, VerificationError{Path: client.config.ExecutablePath, Cause: err}
	}
	if version != client.config.ExpectedVersion {
		return Verification{Version: version, SHA256: digest, Result: result}, VerificationError{Path: client.config.ExecutablePath, Cause: fmt.Errorf("reported version %q does not match pinned version %q", version, client.config.ExpectedVersion)}
	}
	return Verification{Version: version, SHA256: digest, Result: result}, nil
}

func (client Client) Query(parentContext context.Context, identifier string, sql string) QueryResult {
	arguments := []string{"--json", "--disable_database=true", "--disable_events=true", "--disable_extensions=true", sql}
	return client.execute(parentContext, identifier, arguments)
}

func (client Client) execute(parentContext context.Context, identifier string, arguments []string) QueryResult {
	queryContext, cancel := context.WithTimeout(parentContext, client.config.QueryTimeout)
	defer cancel()
	startedAt := time.Now().UTC()
	command := exec.CommandContext(queryContext, client.config.ExecutablePath, arguments...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	completedAt := time.Now().UTC()
	exitCode := 0
	executionError := ""
	if err != nil {
		executionError = err.Error()
		exitCode = -1
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		}
		if queryContext.Err() != nil {
			executionError = fmt.Sprintf("query timeout after %s: %v", client.config.QueryTimeout, queryContext.Err())
		}
	}
	return QueryResult{
		ID:             identifier,
		Arguments:      append([]string(nil), arguments...),
		StartedAt:      startedAt,
		CompletedAt:    completedAt,
		ExitCode:       exitCode,
		StandardOutput: append([]byte(nil), stdout.Bytes()...),
		StandardError:  append([]byte(nil), stderr.Bytes()...),
		ExecutionError: executionError,
	}
}

func (client Client) ExecutablePath() string {
	return client.config.ExecutablePath
}

func (client Client) ValidatePinnedDigest() error {
	digest, err := hashFile(client.config.ExecutablePath)
	if err != nil {
		return VerificationError{Path: client.config.ExecutablePath, Cause: err}
	}
	if digest != client.config.ExpectedSHA256 {
		return VerificationError{Path: client.config.ExecutablePath, Cause: fmt.Errorf("SHA-256 changed during collection: expected %s, calculated %s", client.config.ExpectedSHA256, digest)}
	}
	return nil
}

func parseVersion(output []byte) (string, error) {
	trimmed := strings.TrimSpace(string(output))
	const prefix = "osqueryi version "
	if !strings.HasPrefix(trimmed, prefix) {
		return "", fmt.Errorf("unexpected osquery version output %q", trimmed)
	}
	version := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
	if version == "" || strings.ContainsAny(version, " \t\r\n") {
		return "", fmt.Errorf("unexpected osquery version value %q", version)
	}
	return version, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open executable for SHA-256: %w", err)
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil {
		if closeErr != nil {
			return "", fmt.Errorf("hash executable: %v; close executable: %w", copyErr, closeErr)
		}
		return "", fmt.Errorf("hash executable: %w", copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close executable after SHA-256: %w", closeErr)
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}
