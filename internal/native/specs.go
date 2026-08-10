package native

import "macscope/internal/model"

type findingRule struct {
	Category        model.FindingCategory
	Severity        model.Severity
	Title           string
	Description     string
	Remediation     string
	RemediationStep string
	RequiresAdmin   bool
	RequiresRestart bool
}

type componentIdentity struct {
	Kind       model.AffectedComponentKind
	Identifier string
	Name       string
}

func unprivilegedProbeSpecs() []probeSpec {
	return []probeSpec{
		{
			ID:         "macos-version",
			Area:       model.CoverageAreaHostIdentity,
			Target:     "macOS product version and build",
			Executable: "/usr/bin/sw_vers",
			Arguments:  make([]string, 0),
			Privileged: false,
			Parser:     parseMacOSVersion,
			Rule:       nil,
			Component: componentIdentity{
				Kind:       model.AffectedComponentOS,
				Identifier: "macos",
				Name:       "macOS",
			},
		},
		{
			ID:         "hardware-model",
			Area:       model.CoverageAreaHostIdentity,
			Target:     "Mac hardware model and chip",
			Executable: "/usr/sbin/system_profiler",
			Arguments:  []string{"SPHardwareDataType", "-detailLevel", "mini", "-json"},
			Privileged: false,
			Parser:     parseHardwareModel,
			Rule:       nil,
			Component: componentIdentity{
				Kind:       model.AffectedComponentOS,
				Identifier: "apple-hardware",
				Name:       "Apple hardware",
			},
		},
		{
			ID:         "sip",
			Area:       model.CoverageAreaSecurityControls,
			Target:     "System Integrity Protection",
			Executable: "/usr/bin/csrutil",
			Arguments:  []string{"status"},
			Privileged: false,
			Parser:     parseSIP,
			Rule: &findingRule{
				Category:        model.FindingCategoryConfiguration,
				Severity:        model.SeverityHigh,
				Title:           "System Integrity Protection is disabled",
				Description:     "System Integrity Protection is disabled. This weakens protection for system files and security-sensitive processes; it does not by itself indicate compromise.",
				Remediation:     "Re-enable System Integrity Protection unless a documented research or recovery workflow requires it to remain disabled.",
				RemediationStep: "Restart into macOS Recovery, run csrutil enable in Terminal, and restart macOS.",
				RequiresAdmin:   true,
				RequiresRestart: true,
			},
			Component: componentIdentity{
				Kind:       model.AffectedComponentConfiguration,
				Identifier: "com.apple.sip",
				Name:       "System Integrity Protection",
			},
		},
		{
			ID:         "filevault",
			Area:       model.CoverageAreaSecurityControls,
			Target:     "FileVault volume encryption",
			Executable: "/usr/bin/fdesetup",
			Arguments:  []string{"status"},
			Privileged: false,
			Parser:     parseFileVault,
			Rule: &findingRule{
				Category:        model.FindingCategoryConfiguration,
				Severity:        model.SeverityHigh,
				Title:           "FileVault is disabled",
				Description:     "FileVault is disabled for the startup volume, so data at rest lacks FileVault protection.",
				Remediation:     "Enable FileVault after reviewing recovery-key storage and account authorization requirements.",
				RemediationStep: "Open System Settings, select Privacy & Security, select FileVault, and enable FileVault.",
				RequiresAdmin:   true,
				RequiresRestart: false,
			},
			Component: componentIdentity{
				Kind:       model.AffectedComponentConfiguration,
				Identifier: "com.apple.filevault",
				Name:       "FileVault",
			},
		},
		{
			ID:         "gatekeeper",
			Area:       model.CoverageAreaSecurityControls,
			Target:     "Gatekeeper assessment policy",
			Executable: "/usr/sbin/spctl",
			Arguments:  []string{"--status"},
			Privileged: false,
			Parser:     parseGatekeeper,
			Rule: &findingRule{
				Category:        model.FindingCategoryConfiguration,
				Severity:        model.SeverityHigh,
				Title:           "Gatekeeper assessments are disabled",
				Description:     "Gatekeeper assessments are disabled, reducing application trust checks at launch.",
				Remediation:     "Re-enable Gatekeeper assessments unless a documented, temporary testing workflow requires them to remain disabled.",
				RemediationStep: "Run sudo spctl --global-enable in Terminal, then verify with spctl --status.",
				RequiresAdmin:   true,
				RequiresRestart: false,
			},
			Component: componentIdentity{
				Kind:       model.AffectedComponentConfiguration,
				Identifier: "com.apple.gatekeeper",
				Name:       "Gatekeeper",
			},
		},
		{
			ID:         "application-firewall",
			Area:       model.CoverageAreaSecurityControls,
			Target:     "macOS Application Firewall global state",
			Executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
			Arguments:  []string{"--getglobalstate"},
			Privileged: false,
			Parser:     parseApplicationFirewall,
			Rule: &findingRule{
				Category:        model.FindingCategoryConfiguration,
				Severity:        model.SeverityMedium,
				Title:           "Application Firewall is disabled",
				Description:     "The macOS Application Firewall is disabled. This finding does not establish that services are externally reachable.",
				Remediation:     "Enable the Application Firewall and review per-application allowances.",
				RemediationStep: "Open System Settings, select Network, select Firewall, and enable the firewall.",
				RequiresAdmin:   true,
				RequiresRestart: false,
			},
			Component: componentIdentity{
				Kind:       model.AffectedComponentConfiguration,
				Identifier: "com.apple.application-firewall",
				Name:       "Application Firewall",
			},
		},
		{
			ID:         "firewall-stealth",
			Area:       model.CoverageAreaSecurityControls,
			Target:     "Application Firewall stealth mode",
			Executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
			Arguments:  []string{"--getstealthmode"},
			Privileged: false,
			Parser:     parseFirewallStealth,
			Rule:       nil,
			Component: componentIdentity{
				Kind:       model.AffectedComponentConfiguration,
				Identifier: "com.apple.application-firewall.stealth",
				Name:       "Application Firewall stealth mode",
			},
		},
		{
			ID:         "firewall-block-all",
			Area:       model.CoverageAreaSecurityControls,
			Target:     "Application Firewall Block All mode",
			Executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
			Arguments:  []string{"--getblockall"},
			Privileged: false,
			Parser:     parseFirewallBlockAll,
			Rule:       nil,
			Component: componentIdentity{
				Kind:       model.AffectedComponentConfiguration,
				Identifier: "com.apple.application-firewall.block-all",
				Name:       "Application Firewall Block All mode",
			},
		},
		{
			ID:         "automatic-update-check",
			Area:       model.CoverageAreaSecurityControls,
			Target:     "automatic software update checking",
			Executable: "/usr/sbin/softwareupdate",
			Arguments:  []string{"--schedule"},
			Privileged: false,
			Parser:     parseAutomaticUpdateCheck,
			Rule: &findingRule{
				Category:        model.FindingCategoryConfiguration,
				Severity:        model.SeverityMedium,
				Title:           "Automatic update checking is disabled",
				Description:     "macOS is not scheduled to check automatically for software updates.",
				Remediation:     "Enable automatic update checking and review the separate installation settings for security and system data updates.",
				RemediationStep: "Open System Settings, select General, select Software Update, and enable automatic update checking.",
				RequiresAdmin:   true,
				RequiresRestart: false,
			},
			Component: componentIdentity{
				Kind:       model.AffectedComponentConfiguration,
				Identifier: "com.apple.softwareupdate.automatic-check",
				Name:       "Automatic software update checking",
			},
		},
		{
			ID:         "xprotect-config-version",
			Area:       model.CoverageAreaAppleUpdates,
			Target:     "installed XProtect configuration version",
			Executable: "/usr/bin/plutil",
			Arguments:  []string{"-extract", "CFBundleShortVersionString", "raw", "-o", "-", "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"},
			Privileged: false,
			Parser:     parseXProtectConfigVersion,
			Rule:       nil,
			Component: componentIdentity{
				Kind:       model.AffectedComponentPackage,
				Identifier: "com.apple.XProtect",
				Name:       "XProtect configuration data",
			},
		},
		{
			ID:         "xprotect-framework-version",
			Area:       model.CoverageAreaAppleUpdates,
			Target:     "installed XProtect framework version",
			Executable: "/usr/bin/plutil",
			Arguments:  []string{"-extract", "CFBundleShortVersionString", "raw", "-o", "-", "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"},
			Privileged: false,
			Parser:     parseXProtectFrameworkVersion,
			Rule:       nil,
			Component: componentIdentity{
				Kind:       model.AffectedComponentPackage,
				Identifier: "com.apple.XProtectFramework.XProtect",
				Name:       "XProtect framework",
			},
		},
		{
			ID:         "xprotect-plugin-version",
			Area:       model.CoverageAreaAppleUpdates,
			Target:     "installed XProtect plugin service version",
			Executable: "/usr/bin/plutil",
			Arguments:  []string{"-extract", "CFBundleShortVersionString", "raw", "-o", "-", "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/XPCServices/XProtectPluginService.xpc/Contents/Info.plist"},
			Privileged: false,
			Parser:     parseXProtectPluginVersion,
			Rule:       nil,
			Component: componentIdentity{
				Kind:       model.AffectedComponentPackage,
				Identifier: "com.apple.XprotectFramework.PluginService",
				Name:       "XProtect plugin service",
			},
		},
	}
}

func privilegedProbeSpecs() []probeSpec {
	return []probeSpec{
		{
			ID:         "pf-status",
			Area:       model.CoverageAreaNetworkExposure,
			Target:     "Packet Filter runtime status",
			Executable: "/sbin/pfctl",
			Arguments:  []string{"-s", "info"},
			Privileged: true,
			Parser:     parsePFStatus,
			Rule:       nil,
			Component: componentIdentity{
				Kind:       model.AffectedComponentConfiguration,
				Identifier: "com.apple.pf",
				Name:       "Packet Filter",
			},
		},
		{
			ID:         "remote-login",
			Area:       model.CoverageAreaNetworkExposure,
			Target:     "Remote Login service state",
			Executable: "/usr/sbin/systemsetup",
			Arguments:  []string{"-getremotelogin"},
			Privileged: true,
			Parser:     parseRemoteLogin,
			Rule: &findingRule{
				Category:        model.FindingCategoryNetworkExposure,
				Severity:        model.SeverityLow,
				Title:           "Remote Login is enabled",
				Description:     "Remote Login is enabled. This indicates that SSH service access is configured, but it does not by itself prove LAN or internet reachability.",
				Remediation:     "Disable Remote Login if SSH access is not required, or restrict access to approved users and networks.",
				RemediationStep: "Open System Settings, select General, select Sharing, and disable Remote Login if it is not needed.",
				RequiresAdmin:   true,
				RequiresRestart: false,
			},
			Component: componentIdentity{
				Kind:       model.AffectedComponentService,
				Identifier: "com.openssh.sshd",
				Name:       "Remote Login",
			},
		},
	}
}
