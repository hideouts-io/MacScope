package mscp

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"macscope/internal/artifact"
	"macscope/internal/model"
)

const (
	ToolID            = "mscp"
	Version           = "tahoe_rev3"
	GuidanceVersion   = "Tahoe Guidance, Revision 3.0"
	RepositoryURL     = "https://github.com/usnistgov/macos_security"
	ReleaseURL        = "https://github.com/usnistgov/macos_security/releases/tag/tahoe_rev3"
	ArchiveURL        = "https://github.com/usnistgov/macos_security/archive/refs/tags/tahoe_rev3.tar.gz"
	ArchiveSHA256     = "2dcd1ff9c0f4353432b1b3a2b0cf7fb49a1574c9cf3e7240d3ed1f2f22bd9a61"
	CommitSHA         = "beceac1d21baf9d924c2780f2e248577435bbfb1"
	BaselineID        = "cis_lvl1"
	BaselineRuleCount = 100
	BaselinePath      = "baselines/cis_lvl1.yaml"
	BaselineSHA256    = "950cfea30b45477e55425aba92d40cc9500f70a894eb9e6c15aadf2017614c6d"
	manifestPath      = "evidence/mscp/tahoe_rev3_cis_lvl1_osquery_subset.json"
)

type Rule struct {
	ID              string
	Title           string
	Severity        model.Severity
	SourcePath      string
	SourceSHA256    string
	SQL             string
	ExpectedValues  []string
	Description     string
	Remediation     string
	RemediationStep string
	RequiresAdmin   bool
	RequiresRestart bool
}

type Manifest struct {
	SchemaVersion string           `json:"schema_version"`
	Source        SourceIdentity   `json:"source"`
	Baseline      BaselineIdentity `json:"baseline"`
	Rules         []ManifestRule   `json:"rules"`
	CoverageNote  string           `json:"coverage_note"`
}

type SourceIdentity struct {
	RepositoryURL string    `json:"repository_url"`
	ReleaseURL    string    `json:"release_url"`
	Tag           string    `json:"tag"`
	CommitSHA     string    `json:"commit_sha"`
	ArchiveURL    string    `json:"archive_url"`
	ArchiveSHA256 string    `json:"archive_sha256"`
	ReleasedAt    time.Time `json:"released_at"`
}

type BaselineIdentity struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	RuleCount int    `json:"rule_count"`
}

type ManifestRule struct {
	ID             string         `json:"id"`
	Title          string         `json:"title"`
	Severity       model.Severity `json:"severity"`
	SourcePath     string         `json:"source_path"`
	SourceSHA256   string         `json:"source_sha256"`
	SQL            string         `json:"sql"`
	ExpectedValues []string       `json:"expected_values"`
}

func Rules() []Rule {
	rules := []Rule{
		{
			ID:              "os_sip_enable",
			Title:           "Ensure System Integrity Protection is Enabled",
			Severity:        model.SeverityHigh,
			SourcePath:      "rules/os/os_sip_enable.yaml",
			SourceSHA256:    "32d250d3c0baeade48558332153221335d8f3096fa96b7872a58428f27e291bd",
			SQL:             "SELECT CAST(enabled AS TEXT) AS value FROM sip_config WHERE config_flag = 'sip';",
			ExpectedValues:  []string{"1"},
			Description:     "The mSCP CIS Level 1 rule requires System Integrity Protection to be enabled.",
			Remediation:     "Re-enable System Integrity Protection unless a documented recovery or research workflow requires it to remain disabled.",
			RemediationStep: "Restart into macOS Recovery, run csrutil enable in Terminal, and restart macOS.",
			RequiresAdmin:   true,
			RequiresRestart: true,
		},
		{
			ID:              "os_gatekeeper_enable",
			Title:           "Enable Gatekeeper",
			Severity:        model.SeverityHigh,
			SourcePath:      "rules/os/os_gatekeeper_enable.yaml",
			SourceSHA256:    "caf4eedef92d76e4bd2a411297b0f3013774dcedf9f7defc32db5b2136563151",
			SQL:             "SELECT CAST(assessments_enabled AS TEXT) AS value FROM gatekeeper;",
			ExpectedValues:  []string{"1"},
			Description:     "The mSCP CIS Level 1 rule requires Gatekeeper application assessments to be enabled.",
			Remediation:     "Enable Gatekeeper application assessments through an approved configuration profile or System Settings.",
			RemediationStep: "Open System Settings, select Privacy & Security, and set application downloads to an approved Gatekeeper option.",
			RequiresAdmin:   true,
			RequiresRestart: false,
		},
		{
			ID:              "system_settings_firewall_enable",
			Title:           "Enable macOS Application Firewall",
			Severity:        model.SeverityMedium,
			SourcePath:      "rules/system_settings/system_settings_firewall_enable.yaml",
			SourceSHA256:    "b927ad11dc8f4c347e6cb00b1484e82a050895776b0a5458425e83898dafc91e",
			SQL:             "SELECT CAST(global_state AS TEXT) AS value FROM alf;",
			ExpectedValues:  []string{"1", "2"},
			Description:     "The mSCP CIS Level 1 rule requires the macOS Application Firewall to be enabled.",
			Remediation:     "Enable the macOS Application Firewall and review its application allowances.",
			RemediationStep: "Open System Settings, select Network, select Firewall, and enable the firewall.",
			RequiresAdmin:   true,
			RequiresRestart: false,
		},
		{
			ID:              "system_settings_firewall_stealth_mode_enable",
			Title:           "Enable Firewall Stealth Mode",
			Severity:        model.SeverityMedium,
			SourcePath:      "rules/system_settings/system_settings_firewall_stealth_mode_enable.yaml",
			SourceSHA256:    "06583534f0d8c75dd8679f438a5d36f1cca453f13ce53842c81b226221282343",
			SQL:             "SELECT CAST(stealth_enabled AS TEXT) AS value FROM alf;",
			ExpectedValues:  []string{"1"},
			Description:     "The mSCP CIS Level 1 rule requires Application Firewall stealth mode to be enabled, subject to operational compatibility review.",
			Remediation:     "Enable firewall stealth mode after confirming that approved remote management and compliance tooling remains functional.",
			RemediationStep: "Open System Settings, select Network, select Firewall, open Options, and enable stealth mode.",
			RequiresAdmin:   true,
			RequiresRestart: false,
		},
	}
	return copyRules(rules)
}

func SupportsMacOS(macOSVersion string) bool {
	major, _, _ := strings.Cut(macOSVersion, ".")
	return major == "26"
}

func ReleaseTimestamp() time.Time {
	return time.Date(2026, time.June, 22, 14, 39, 4, 0, time.UTC)
}

func ToolRecord() model.ToolRecord {
	return model.ToolRecord{
		ID:      ToolID,
		Name:    "macOS Security Compliance Project",
		Version: GuidanceVersion,
		Kind:    model.ToolKindMatcher,
		Origin:  ReleaseURL,
		Data: &model.DataIdentity{
			Version:   Version + "@" + CommitSHA,
			UpdatedAt: ReleaseTimestamp(),
			SHA256:    ArchiveSHA256,
		},
	}
}

func ManifestArtifact() (artifact.Record, model.ArtifactReference, error) {
	rules := Rules()
	manifestRules := make([]ManifestRule, 0, len(rules))
	for _, rule := range rules {
		manifestRules = append(manifestRules, ManifestRule{
			ID:             rule.ID,
			Title:          rule.Title,
			Severity:       rule.Severity,
			SourcePath:     rule.SourcePath,
			SourceSHA256:   rule.SourceSHA256,
			SQL:            rule.SQL,
			ExpectedValues: append([]string(nil), rule.ExpectedValues...),
		})
	}
	manifest := Manifest{
		SchemaVersion: "1",
		Source: SourceIdentity{
			RepositoryURL: RepositoryURL,
			ReleaseURL:    ReleaseURL,
			Tag:           Version,
			CommitSHA:     CommitSHA,
			ArchiveURL:    ArchiveURL,
			ArchiveSHA256: ArchiveSHA256,
			ReleasedAt:    ReleaseTimestamp(),
		},
		Baseline: BaselineIdentity{
			ID:        BaselineID,
			Path:      BaselinePath,
			SHA256:    BaselineSHA256,
			RuleCount: BaselineRuleCount,
		},
		Rules:        manifestRules,
		CoverageNote: fmt.Sprintf("MacScope evaluates %d of %d CIS Level 1 rules using fixed read-only osquery SQL; it does not claim full baseline compliance.", len(rules), BaselineRuleCount),
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return artifact.Record{}, model.ArtifactReference{}, fmt.Errorf("encode mSCP adapter manifest: %w", err)
	}
	encoded = append(encoded, '\n')
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	return artifact.Record{Path: manifestPath, Content: encoded}, model.ArtifactReference{
		Path:      manifestPath,
		SHA256:    digest,
		MediaType: "application/json",
	}, nil
}

func IsExpected(rule Rule, value string) bool {
	return slices.Contains(rule.ExpectedValues, value)
}

func RuleReference(rule Rule) string {
	return RepositoryURL + "/blob/" + Version + "/" + rule.SourcePath
}

func copyRules(rules []Rule) []Rule {
	copied := make([]Rule, len(rules))
	for index, rule := range rules {
		copied[index] = rule
		copied[index].ExpectedValues = append([]string(nil), rule.ExpectedValues...)
	}
	return copied
}
