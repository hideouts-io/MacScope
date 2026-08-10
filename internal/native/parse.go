package native

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

type assessmentState string

const (
	assessmentStatePass         assessmentState = "pass"
	assessmentStateNoncompliant assessmentState = "noncompliant"
	assessmentStateObserved     assessmentState = "observed"
)

type HostDetails struct {
	MacOSVersion          string
	MacOSBuild            string
	ModelID               string
	Chip                  string
	XProtectConfigVersion string
	XProtectVersion       string
	XProtectPluginVersion string
}

type assessment struct {
	State       assessmentState
	Summary     string
	HostDetails HostDetails
}

func parseMacOSVersion(result ProbeResult) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}
		key, value, found := strings.Cut(trimmedLine, ":")
		if !found || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return assessment{}, ProbeExecutionError{ProbeID: result.ID, Message: fmt.Sprintf("unexpected sw_vers line %q", line)}
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	productVersion := values["ProductVersion"]
	buildVersion := values["BuildVersion"]
	if productVersion == "" || buildVersion == "" {
		return assessment{}, ProbeExecutionError{ProbeID: result.ID, Message: fmt.Sprintf("sw_vers output is missing ProductVersion or BuildVersion: %q", output)}
	}
	return assessment{
		State:   assessmentStateObserved,
		Summary: fmt.Sprintf("macOS %s build %s", productVersion, buildVersion),
		HostDetails: HostDetails{
			MacOSVersion: productVersion,
			MacOSBuild:   buildVersion,
		},
	}, nil
}

func parseHardwareModel(result ProbeResult) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	var payload struct {
		Hardware []struct {
			MachineModel string `json:"machine_model"`
			ChipType     string `json:"chip_type"`
		} `json:"SPHardwareDataType"`
	}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		return assessment{}, ProbeExecutionError{ProbeID: result.ID, Message: fmt.Sprintf("decode system_profiler JSON: %v", err)}
	}
	if len(payload.Hardware) != 1 {
		return assessment{}, ProbeExecutionError{ProbeID: result.ID, Message: fmt.Sprintf("system_profiler returned %d hardware records; expected 1", len(payload.Hardware))}
	}
	hardware := payload.Hardware[0]
	if strings.TrimSpace(hardware.MachineModel) == "" || strings.TrimSpace(hardware.ChipType) == "" {
		return assessment{}, ProbeExecutionError{ProbeID: result.ID, Message: "system_profiler hardware record is missing machine_model or chip_type"}
	}
	return assessment{
		State:   assessmentStateObserved,
		Summary: fmt.Sprintf("hardware model %s with %s", hardware.MachineModel, hardware.ChipType),
		HostDetails: HostDetails{
			ModelID: hardware.MachineModel,
			Chip:    hardware.ChipType,
		},
	}, nil
}

func parseSIP(result ProbeResult) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	lowerOutput := strings.ToLower(output)
	switch {
	case strings.Contains(lowerOutput, "system integrity protection status: enabled"):
		return assessment{State: assessmentStatePass, Summary: "System Integrity Protection is enabled"}, nil
	case strings.Contains(lowerOutput, "system integrity protection status: disabled"):
		return assessment{State: assessmentStateNoncompliant, Summary: "System Integrity Protection is disabled"}, nil
	default:
		return assessment{}, unexpectedState(result.ID, output)
	}
}

func parseFileVault(result ProbeResult) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	lowerOutput := strings.ToLower(output)
	switch {
	case strings.Contains(lowerOutput, "filevault is on"):
		return assessment{State: assessmentStatePass, Summary: "FileVault is enabled"}, nil
	case strings.Contains(lowerOutput, "filevault is off"):
		return assessment{State: assessmentStateNoncompliant, Summary: "FileVault is disabled"}, nil
	default:
		return assessment{}, unexpectedState(result.ID, output)
	}
}

func parseGatekeeper(result ProbeResult) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	lowerOutput := strings.ToLower(output)
	switch {
	case strings.Contains(lowerOutput, "assessments enabled"):
		return assessment{State: assessmentStatePass, Summary: "Gatekeeper assessments are enabled"}, nil
	case strings.Contains(lowerOutput, "assessments disabled"):
		return assessment{State: assessmentStateNoncompliant, Summary: "Gatekeeper assessments are disabled"}, nil
	default:
		return assessment{}, unexpectedState(result.ID, output)
	}
}

func parseApplicationFirewall(result ProbeResult) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	lowerOutput := strings.ToLower(output)
	switch {
	case strings.Contains(lowerOutput, "firewall is enabled"):
		return assessment{State: assessmentStatePass, Summary: "Application Firewall is enabled"}, nil
	case strings.Contains(lowerOutput, "firewall is disabled"):
		return assessment{State: assessmentStateNoncompliant, Summary: "Application Firewall is disabled"}, nil
	default:
		return assessment{}, unexpectedState(result.ID, output)
	}
}

func parseFirewallStealth(result ProbeResult) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	lowerOutput := strings.ToLower(output)
	switch {
	case strings.Contains(lowerOutput, "stealth mode is on"):
		return assessment{State: assessmentStateObserved, Summary: "Application Firewall stealth mode is enabled"}, nil
	case strings.Contains(lowerOutput, "stealth mode is off"):
		return assessment{State: assessmentStateObserved, Summary: "Application Firewall stealth mode is disabled"}, nil
	default:
		return assessment{}, unexpectedState(result.ID, output)
	}
}

func parseFirewallBlockAll(result ProbeResult) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	lowerOutput := strings.ToLower(output)
	switch {
	case strings.Contains(lowerOutput, "block all state set to enabled"):
		return assessment{State: assessmentStateObserved, Summary: "Application Firewall Block All mode is enabled"}, nil
	case strings.Contains(lowerOutput, "block all state set to disabled"):
		return assessment{State: assessmentStateObserved, Summary: "Application Firewall Block All mode is disabled"}, nil
	default:
		return assessment{}, unexpectedState(result.ID, output)
	}
}

func parseAutomaticUpdateCheck(result ProbeResult) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	lowerOutput := strings.ToLower(output)
	switch {
	case strings.Contains(lowerOutput, "automatic checking for updates is turned on"):
		return assessment{State: assessmentStatePass, Summary: "Automatic software update checking is enabled"}, nil
	case strings.Contains(lowerOutput, "automatic checking for updates is turned off"):
		return assessment{State: assessmentStateNoncompliant, Summary: "Automatic software update checking is disabled"}, nil
	default:
		return assessment{}, unexpectedState(result.ID, output)
	}
}

func parseXProtectConfigVersion(result ProbeResult) (assessment, error) {
	return parseXProtectVersion(result, "XProtect configuration", func(version string) HostDetails {
		return HostDetails{XProtectConfigVersion: version}
	})
}

func parseXProtectFrameworkVersion(result ProbeResult) (assessment, error) {
	return parseXProtectVersion(result, "XProtect framework", func(version string) HostDetails {
		return HostDetails{XProtectVersion: version}
	})
}

func parseXProtectPluginVersion(result ProbeResult) (assessment, error) {
	return parseXProtectVersion(result, "XProtect plugin service", func(version string) HostDetails {
		return HostDetails{XProtectPluginVersion: version}
	})
}

func parseXProtectVersion(result ProbeResult, componentName string, buildHostDetails func(string) HostDetails) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	version := strings.TrimSpace(output)
	for _, character := range version {
		if character < '0' || character > '9' {
			return assessment{}, ProbeExecutionError{ProbeID: result.ID, Message: fmt.Sprintf("%s version %q is not a positive integer", componentName, version)}
		}
	}
	if version == "" || version == "0" {
		return assessment{}, ProbeExecutionError{ProbeID: result.ID, Message: fmt.Sprintf("%s version %q is not a positive integer", componentName, version)}
	}
	return assessment{
		State:       assessmentStateObserved,
		Summary:     fmt.Sprintf("%s version %s", componentName, version),
		HostDetails: buildHostDetails(version),
	}, nil
}

func parsePFStatus(result ProbeResult) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	lowerOutput := strings.ToLower(output)
	switch {
	case strings.Contains(lowerOutput, "status: enabled"):
		return assessment{State: assessmentStateObserved, Summary: "Packet Filter is enabled at runtime"}, nil
	case strings.Contains(lowerOutput, "status: disabled"):
		return assessment{State: assessmentStateObserved, Summary: "Packet Filter is disabled at runtime"}, nil
	default:
		return assessment{}, unexpectedState(result.ID, output)
	}
}

func parseRemoteLogin(result ProbeResult) (assessment, error) {
	output, err := successfulOutput(result)
	if err != nil {
		return assessment{}, err
	}
	lowerOutput := strings.ToLower(output)
	if strings.Contains(lowerOutput, "need administrator access") {
		return assessment{}, ProbeExecutionError{ProbeID: result.ID, Message: "systemsetup did not receive administrator access"}
	}
	switch {
	case strings.Contains(lowerOutput, "remote login: on"):
		return assessment{State: assessmentStateNoncompliant, Summary: "Remote Login is enabled"}, nil
	case strings.Contains(lowerOutput, "remote login: off"):
		return assessment{State: assessmentStatePass, Summary: "Remote Login is disabled"}, nil
	default:
		return assessment{}, unexpectedState(result.ID, output)
	}
}

func successfulOutput(result ProbeResult) (string, error) {
	if !utf8.Valid(result.StandardOutput) || !utf8.Valid(result.StandardError) {
		return "", ProbeExecutionError{ProbeID: result.ID, Message: "command output is not valid UTF-8; inspect the base64 evidence artifact"}
	}
	combinedOutput := strings.TrimSpace(strings.TrimSpace(string(result.StandardOutput)) + "\n" + strings.TrimSpace(string(result.StandardError)))
	if result.ExecutionError != "" {
		return "", ProbeExecutionError{ProbeID: result.ID, Message: fmt.Sprintf("execution error: %s; exit code: %d; output: %q", result.ExecutionError, result.ExitCode, combinedOutput)}
	}
	if result.ExitCode != 0 {
		return "", ProbeExecutionError{ProbeID: result.ID, Message: fmt.Sprintf("exit code %d; output: %q", result.ExitCode, combinedOutput)}
	}
	if combinedOutput == "" {
		return "", ProbeExecutionError{ProbeID: result.ID, Message: "command returned empty output"}
	}
	return combinedOutput, nil
}

func unexpectedState(probeID string, output string) ProbeExecutionError {
	return ProbeExecutionError{ProbeID: probeID, Message: fmt.Sprintf("unrecognized command output %q", output)}
}
