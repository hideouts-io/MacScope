package supplychain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	SyftToolID                  = "syft"
	SyftExpectedVersion         = "1.50.0"
	SyftExpectedCommit          = "16223e6dd7893fe578787658ceb876257483d404"
	SyftExpectedExecutableHash  = "5d59c9e6fa641793ddb48bc90b5b7ad63bf7303a52835b75b1beee3757463998"
	SyftOriginURL               = "https://github.com/anchore/syft/releases/tag/v1.50.0"
	GrypeToolID                 = "grype"
	GrypeExpectedVersion        = "0.116.1"
	GrypeExpectedCommit         = "30394f177175da63ae36b35cdd809c248eb4de7f"
	GrypeExpectedExecutableHash = "361b86bc5906fa38ad24cc8a0c2ce9128ac7d8931e82505236a8d0b16bbf2fbe"
	GrypeOriginURL              = "https://github.com/anchore/grype/releases/tag/v0.116.1"
)

type ClientConfig struct {
	SyftExecutablePath     string
	SyftExpectedVersion    string
	SyftExpectedCommit     string
	SyftExpectedSHA256     string
	SyftConfigPath         string
	GrypeExecutablePath    string
	GrypeExpectedVersion   string
	GrypeExpectedCommit    string
	GrypeExpectedSHA256    string
	GrypeConfigPath        string
	GrypeDatabaseDirectory string
	SyftTimeout            time.Duration
	GrypeTimeout           time.Duration
	DatabaseTimeout        time.Duration
	DatabaseUpdateAttempts int
	DatabaseRetryDelays    []time.Duration
}

type Client struct {
	config ClientConfig
}

type EnvironmentSetting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CommandResult struct {
	ID             string
	ExecutablePath string
	Arguments      []string
	Environment    []EnvironmentSetting
	InputSHA256    string
	StartedAt      time.Time
	CompletedAt    time.Time
	ExitCode       int
	StandardOutput []byte
	StandardError  []byte
	ExecutionError string
}

type ExecutableVerification struct {
	Version string
	Commit  string
	SHA256  string
	Result  CommandResult
}

type VerificationError struct {
	Tool  string
	Path  string
	Cause error
}

func (err VerificationError) Error() string {
	return fmt.Sprintf("verify pinned %s executable %q: %v", err.Tool, err.Path, err.Cause)
}

func (err VerificationError) Unwrap() error {
	return err.Cause
}

type versionDocument struct {
	Application string `json:"application"`
	GitCommit   string `json:"gitCommit"`
	Platform    string `json:"platform"`
	Version     string `json:"version"`
}

func NewClient(config ClientConfig) (Client, error) {
	if err := validateClientConfig(config); err != nil {
		return Client{}, err
	}
	return Client{config: copyClientConfig(config)}, nil
}

func validateClientConfig(config ClientConfig) error {
	paths := []struct {
		name string
		path string
	}{
		{name: "syft executable", path: config.SyftExecutablePath},
		{name: "syft configuration", path: config.SyftConfigPath},
		{name: "grype executable", path: config.GrypeExecutablePath},
		{name: "grype configuration", path: config.GrypeConfigPath},
		{name: "grype database directory", path: config.GrypeDatabaseDirectory},
	}
	for _, item := range paths {
		if !filepath.IsAbs(item.path) {
			return fmt.Errorf("%s path %q must be absolute", item.name, item.path)
		}
	}
	versions := []struct {
		name    string
		version string
		commit  string
		digest  string
	}{
		{name: SyftToolID, version: config.SyftExpectedVersion, commit: config.SyftExpectedCommit, digest: config.SyftExpectedSHA256},
		{name: GrypeToolID, version: config.GrypeExpectedVersion, commit: config.GrypeExpectedCommit, digest: config.GrypeExpectedSHA256},
	}
	for _, item := range versions {
		if strings.TrimSpace(item.version) == "" {
			return fmt.Errorf("%s expected version must not be empty", item.name)
		}
		if !isLowercaseSHA256(item.commit) {
			return fmt.Errorf("%s expected commit %q must contain 40 lowercase hexadecimal characters", item.name, item.commit)
		}
		if !isLowercaseSHA256(item.digest) {
			return fmt.Errorf("%s expected SHA-256 %q must contain 64 lowercase hexadecimal characters", item.name, item.digest)
		}
	}
	if config.SyftTimeout <= 0 || config.GrypeTimeout <= 0 || config.DatabaseTimeout <= 0 {
		return fmt.Errorf("syft, grype, and database command timeouts must all be positive")
	}
	if config.DatabaseUpdateAttempts < 1 {
		return fmt.Errorf("grype database update attempts must be at least 1; received %d", config.DatabaseUpdateAttempts)
	}
	if len(config.DatabaseRetryDelays) != config.DatabaseUpdateAttempts-1 {
		return fmt.Errorf("grype database retry delay count must be attempts minus one; received %d delays for %d attempts", len(config.DatabaseRetryDelays), config.DatabaseUpdateAttempts)
	}
	for index, delay := range config.DatabaseRetryDelays {
		if delay < 0 {
			return fmt.Errorf("grype database retry delay %d must not be negative; received %s", index, delay)
		}
	}
	return nil
}

func copyClientConfig(config ClientConfig) ClientConfig {
	copied := config
	copied.DatabaseRetryDelays = append([]time.Duration(nil), config.DatabaseRetryDelays...)
	return copied
}

func (client Client) VerifySyft(parentContext context.Context) (ExecutableVerification, error) {
	return verifyExecutable(parentContext, executableSpec{
		ToolID:          SyftToolID,
		Path:            client.config.SyftExecutablePath,
		ExpectedVersion: client.config.SyftExpectedVersion,
		ExpectedCommit:  client.config.SyftExpectedCommit,
		ExpectedSHA256:  client.config.SyftExpectedSHA256,
		Timeout:         client.config.SyftTimeout,
		VersionArgs:     []string{"version", "--output", "json"},
	})
}

func (client Client) VerifyGrype(parentContext context.Context) (ExecutableVerification, error) {
	return verifyExecutable(parentContext, executableSpec{
		ToolID:          GrypeToolID,
		Path:            client.config.GrypeExecutablePath,
		ExpectedVersion: client.config.GrypeExpectedVersion,
		ExpectedCommit:  client.config.GrypeExpectedCommit,
		ExpectedSHA256:  client.config.GrypeExpectedSHA256,
		Timeout:         client.config.GrypeTimeout,
		VersionArgs:     []string{"version", "--output", "json"},
	})
}

type executableSpec struct {
	ToolID          string
	Path            string
	ExpectedVersion string
	ExpectedCommit  string
	ExpectedSHA256  string
	Timeout         time.Duration
	VersionArgs     []string
}

func verifyExecutable(parentContext context.Context, spec executableSpec) (ExecutableVerification, error) {
	fileInfo, err := os.Stat(spec.Path)
	if err != nil {
		return ExecutableVerification{}, VerificationError{Tool: spec.ToolID, Path: spec.Path, Cause: fmt.Errorf("stat executable: %w", err)}
	}
	if !fileInfo.Mode().IsRegular() {
		return ExecutableVerification{}, VerificationError{Tool: spec.ToolID, Path: spec.Path, Cause: fmt.Errorf("path is not a regular file")}
	}
	if fileInfo.Mode().Perm()&0o111 == 0 {
		return ExecutableVerification{}, VerificationError{Tool: spec.ToolID, Path: spec.Path, Cause: fmt.Errorf("file has no executable permission bits")}
	}
	digest, err := hashFile(spec.Path)
	if err != nil {
		return ExecutableVerification{}, VerificationError{Tool: spec.ToolID, Path: spec.Path, Cause: err}
	}
	if digest != spec.ExpectedSHA256 {
		return ExecutableVerification{SHA256: digest}, VerificationError{Tool: spec.ToolID, Path: spec.Path, Cause: fmt.Errorf("SHA-256 mismatch: expected %s, calculated %s", spec.ExpectedSHA256, digest)}
	}
	result := execute(parentContext, spec.Path, spec.VersionArgs, nil, nil, spec.ToolID+"-version", spec.Timeout)
	verification := ExecutableVerification{SHA256: digest, Result: result}
	if err := successfulCommand(result); err != nil {
		return verification, VerificationError{Tool: spec.ToolID, Path: spec.Path, Cause: fmt.Errorf("version command failed: %w", err)}
	}
	version, commit, err := parseVersionDocument(result.StandardOutput, spec.ToolID)
	verification.Version = version
	verification.Commit = commit
	if err != nil {
		return verification, VerificationError{Tool: spec.ToolID, Path: spec.Path, Cause: err}
	}
	if version != spec.ExpectedVersion {
		return verification, VerificationError{Tool: spec.ToolID, Path: spec.Path, Cause: fmt.Errorf("reported version %q does not match pinned version %q", version, spec.ExpectedVersion)}
	}
	if commit != spec.ExpectedCommit {
		return verification, VerificationError{Tool: spec.ToolID, Path: spec.Path, Cause: fmt.Errorf("reported commit %q does not match pinned commit %q", commit, spec.ExpectedCommit)}
	}
	return verification, nil
}

func parseVersionDocument(output []byte, application string) (string, string, error) {
	var document versionDocument
	if err := json.Unmarshal(output, &document); err != nil {
		return "", "", fmt.Errorf("decode %s version JSON: %w", application, err)
	}
	if document.Application != application {
		return document.Version, document.GitCommit, fmt.Errorf("validate %s version JSON: application %q does not match %q", application, document.Application, application)
	}
	if strings.TrimSpace(document.Version) == "" || strings.TrimSpace(document.GitCommit) == "" {
		return document.Version, document.GitCommit, fmt.Errorf("validate %s version JSON: version and gitCommit are required", application)
	}
	if document.Platform != "darwin/arm64" {
		return document.Version, document.GitCommit, fmt.Errorf("validate %s version JSON: platform %q does not match darwin/arm64", application, document.Platform)
	}
	return document.Version, document.GitCommit, nil
}

func (client Client) RunSyft(parentContext context.Context, macOSVersion string, scope SyftScope) CommandResult {
	arguments := []string{
		"--config", scope.ConfigPath,
		"scan", "dir:/",
		"--source-name", "macOS-startup-volume",
		"--source-version", macOSVersion,
		"--output", "syft-json",
	}
	return execute(parentContext, client.config.SyftExecutablePath, arguments, nil, nil, "filesystem-sbom", client.config.SyftTimeout)
}

func (client Client) RunGrypeDatabaseUpdate(parentContext context.Context, attempt int) CommandResult {
	arguments := []string{"--config", client.config.GrypeConfigPath, "db", "update"}
	return execute(parentContext, client.config.GrypeExecutablePath, arguments, grypeEnvironment(client.config.GrypeDatabaseDirectory), nil, fmt.Sprintf("db-update-attempt-%d", attempt), client.config.DatabaseTimeout)
}

func (client Client) RunGrypeDatabaseStatus(parentContext context.Context) CommandResult {
	arguments := []string{"--config", client.config.GrypeConfigPath, "db", "status", "--output", "json"}
	return execute(parentContext, client.config.GrypeExecutablePath, arguments, grypeEnvironment(client.config.GrypeDatabaseDirectory), nil, "db-status", client.config.DatabaseTimeout)
}

func (client Client) RunGrype(parentContext context.Context, syftSBOM []byte) CommandResult {
	arguments := []string{"--config", client.config.GrypeConfigPath, "--output", "json", "--by-cve"}
	return execute(parentContext, client.config.GrypeExecutablePath, arguments, grypeEnvironment(client.config.GrypeDatabaseDirectory), syftSBOM, "vulnerability-match", client.config.GrypeTimeout)
}

func (client Client) ValidateSyftDigest() error {
	return validatePinnedDigest(SyftToolID, client.config.SyftExecutablePath, client.config.SyftExpectedSHA256)
}

func (client Client) ValidateGrypeDigest() error {
	return validatePinnedDigest(GrypeToolID, client.config.GrypeExecutablePath, client.config.GrypeExpectedSHA256)
}

func validatePinnedDigest(toolID string, path string, expectedSHA256 string) error {
	digest, err := hashFile(path)
	if err != nil {
		return VerificationError{Tool: toolID, Path: path, Cause: err}
	}
	if digest != expectedSHA256 {
		return VerificationError{Tool: toolID, Path: path, Cause: fmt.Errorf("SHA-256 changed during collection: expected %s, calculated %s", expectedSHA256, digest)}
	}
	return nil
}

func (client Client) Config() ClientConfig {
	return copyClientConfig(client.config)
}

func grypeEnvironment(databaseDirectory string) []EnvironmentSetting {
	return []EnvironmentSetting{
		{Name: "GRYPE_DB_CACHE_DIR", Value: databaseDirectory},
		{Name: "GRYPE_DB_AUTO_UPDATE", Value: "false"},
		{Name: "GRYPE_CHECK_FOR_APP_UPDATE", Value: "false"},
	}
}

func execute(parentContext context.Context, executablePath string, arguments []string, environment []EnvironmentSetting, standardInput []byte, identifier string, timeout time.Duration) CommandResult {
	commandContext, cancel := context.WithTimeout(parentContext, timeout)
	defer cancel()
	startedAt := time.Now().UTC()
	command := exec.CommandContext(commandContext, executablePath, arguments...)
	if standardInput != nil {
		command.Stdin = bytes.NewReader(standardInput)
	}
	command.Env = commandEnvironment(environment)
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
		if commandContext.Err() != nil {
			executionError = fmt.Sprintf("command timeout after %s: %v", timeout, commandContext.Err())
		}
	}
	inputDigest := ""
	if standardInput != nil {
		inputDigest = fmt.Sprintf("%x", sha256.Sum256(standardInput))
	}
	return CommandResult{
		ID:             identifier,
		ExecutablePath: executablePath,
		Arguments:      append([]string(nil), arguments...),
		Environment:    append([]EnvironmentSetting(nil), environment...),
		InputSHA256:    inputDigest,
		StartedAt:      startedAt,
		CompletedAt:    completedAt,
		ExitCode:       exitCode,
		StandardOutput: append([]byte(nil), stdout.Bytes()...),
		StandardError:  append([]byte(nil), stderr.Bytes()...),
		ExecutionError: executionError,
	}
}

func commandEnvironment(settings []EnvironmentSetting) []string {
	names := make(map[string]struct{}, len(settings))
	for _, setting := range settings {
		names[setting.Name] = struct{}{}
	}
	base := make([]string, 0, len(os.Environ())+len(settings))
	for _, item := range os.Environ() {
		name, _, found := strings.Cut(item, "=")
		if _, replaced := names[name]; found && replaced {
			continue
		}
		base = append(base, item)
	}
	for _, setting := range settings {
		base = append(base, setting.Name+"="+setting.Value)
	}
	return base
}

func successfulCommand(result CommandResult) error {
	if result.ExecutionError != "" || result.ExitCode != 0 {
		return fmt.Errorf("command %s failed: exit_code=%d execution_error=%q stderr=%q", result.ID, result.ExitCode, result.ExecutionError, string(result.StandardError))
	}
	if len(result.StandardOutput) == 0 && result.ID != "db-update-attempt-1" && !strings.HasPrefix(result.ID, "db-update-attempt-") {
		return fmt.Errorf("command %s returned empty standard output", result.ID)
	}
	return nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for SHA-256: %w", err)
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil {
		if closeErr != nil {
			return "", fmt.Errorf("hash file: %v; close file: %w", copyErr, closeErr)
		}
		return "", fmt.Errorf("hash file: %w", copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close file after SHA-256: %w", closeErr)
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

func isLowercaseSHA256(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
