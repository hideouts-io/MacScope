package native

import (
	"testing"
	"time"
)

func TestSecurityControlParsers(t *testing.T) {
	testCases := []struct {
		name          string
		parser        probeParser
		output        string
		expectedState assessmentState
	}{
		{name: "SIP enabled", parser: parseSIP, output: "System Integrity Protection status: enabled.\n", expectedState: assessmentStatePass},
		{name: "SIP disabled", parser: parseSIP, output: "System Integrity Protection status: disabled.\n", expectedState: assessmentStateNoncompliant},
		{name: "FileVault enabled", parser: parseFileVault, output: "FileVault is On.\n", expectedState: assessmentStatePass},
		{name: "FileVault disabled", parser: parseFileVault, output: "FileVault is Off.\n", expectedState: assessmentStateNoncompliant},
		{name: "Gatekeeper enabled", parser: parseGatekeeper, output: "assessments enabled\n", expectedState: assessmentStatePass},
		{name: "Gatekeeper disabled", parser: parseGatekeeper, output: "assessments disabled\n", expectedState: assessmentStateNoncompliant},
		{name: "Firewall enabled", parser: parseApplicationFirewall, output: "Firewall is enabled. (State = 1)\n", expectedState: assessmentStatePass},
		{name: "Firewall disabled", parser: parseApplicationFirewall, output: "Firewall is disabled. (State = 0)\n", expectedState: assessmentStateNoncompliant},
		{name: "Stealth enabled observation", parser: parseFirewallStealth, output: "Firewall stealth mode is on\n", expectedState: assessmentStateObserved},
		{name: "Stealth disabled observation", parser: parseFirewallStealth, output: "Firewall stealth mode is off\n", expectedState: assessmentStateObserved},
		{name: "Block All enabled observation", parser: parseFirewallBlockAll, output: "Firewall has block all state set to enabled.\n", expectedState: assessmentStateObserved},
		{name: "Block All disabled observation", parser: parseFirewallBlockAll, output: "Firewall has block all state set to disabled.\n", expectedState: assessmentStateObserved},
		{name: "Automatic update check enabled", parser: parseAutomaticUpdateCheck, output: "Automatic checking for updates is turned on\n", expectedState: assessmentStatePass},
		{name: "Automatic update check disabled", parser: parseAutomaticUpdateCheck, output: "Automatic checking for updates is turned off\n", expectedState: assessmentStateNoncompliant},
		{name: "PF enabled observation", parser: parsePFStatus, output: "Status: Enabled for 0 days 00:01:00\n", expectedState: assessmentStateObserved},
		{name: "PF disabled observation", parser: parsePFStatus, output: "Status: Disabled\n", expectedState: assessmentStateObserved},
		{name: "Remote Login enabled", parser: parseRemoteLogin, output: "Remote Login: On\n", expectedState: assessmentStateNoncompliant},
		{name: "Remote Login disabled", parser: parseRemoteLogin, output: "Remote Login: Off\n", expectedState: assessmentStatePass},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := successfulProbeResult("test-probe", testCase.output)
			parsed, err := testCase.parser(result)
			if err != nil {
				t.Fatalf("parser returned an error: %v", err)
			}
			if parsed.State != testCase.expectedState {
				t.Fatalf("state = %q, want %q", parsed.State, testCase.expectedState)
			}
		})
	}
}

func TestParseMacOSVersion(t *testing.T) {
	result := successfulProbeResult("macos-version", "ProductName:\t\tmacOS\nProductVersion:\t\t26.4\nBuildVersion:\t\t25E246\n")
	parsed, err := parseMacOSVersion(result)
	if err != nil {
		t.Fatalf("parseMacOSVersion returned an error: %v", err)
	}
	if parsed.HostDetails.MacOSVersion != "26.4" || parsed.HostDetails.MacOSBuild != "25E246" {
		t.Fatalf("host details = %#v, want version 26.4 build 25E246", parsed.HostDetails)
	}
}

func TestParseHardwareModelIgnoresUnrelatedFields(t *testing.T) {
	output := `{"SPHardwareDataType":[{"machine_model":"Mac15,10","chip_type":"Apple M3 Max","serial_number":"not-collected-by-real-mini-probe"}]}`
	result := successfulProbeResult("hardware-model", output)
	parsed, err := parseHardwareModel(result)
	if err != nil {
		t.Fatalf("parseHardwareModel returned an error: %v", err)
	}
	if parsed.HostDetails.ModelID != "Mac15,10" || parsed.HostDetails.Chip != "Apple M3 Max" {
		t.Fatalf("host details = %#v, want Mac15,10 and Apple M3 Max", parsed.HostDetails)
	}
}

func TestParseRemoteLoginRejectsPermissionMessageWithZeroExit(t *testing.T) {
	result := successfulProbeResult("remote-login", "You need administrator access to run this tool... exiting!\n")
	_, err := parseRemoteLogin(result)
	if err == nil {
		t.Fatal("parseRemoteLogin returned nil error for administrator-access failure")
	}
}

func TestParserRejectsNonzeroExit(t *testing.T) {
	result := successfulProbeResult("filevault", "")
	result.ExitCode = 15
	result.StandardError = []byte("Error: Unknown volume or device specifier: '/'.\n")
	result.ExecutionError = "exit status 15"
	_, err := parseFileVault(result)
	if err == nil {
		t.Fatal("parseFileVault returned nil error for nonzero exit")
	}
}

func successfulProbeResult(id string, standardOutput string) ProbeResult {
	startedAt := time.Date(2026, time.August, 9, 10, 0, 0, 0, time.UTC)
	return ProbeResult{
		ID:             id,
		Executable:     "/usr/bin/test",
		Arguments:      make([]string, 0),
		Privileged:     false,
		StartedAt:      startedAt,
		CompletedAt:    startedAt.Add(time.Millisecond),
		ExitCode:       0,
		StandardOutput: []byte(standardOutput),
		StandardError:  make([]byte, 0),
		ExecutionError: "",
	}
}
