package supplychain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"macscope/internal/model"
)

func TestValidateUserExclusionsAcceptsExistingFilesAndDirectories(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "excluded-directory")
	if err := os.Mkdir(directory, 0o750); err != nil {
		t.Fatalf("create excluded directory: %v", err)
	}
	file := filepath.Join(root, "excluded-file.json")
	if err := os.WriteFile(file, []byte("{}"), 0o640); err != nil {
		t.Fatalf("create excluded file: %v", err)
	}
	exclusions, err := validateUserExclusions([]string{file, directory, file})
	if err != nil {
		t.Fatalf("validateUserExclusions returned an error: %v", err)
	}
	if len(exclusions) != 2 {
		t.Fatalf("validated exclusions = %#v, want two deduplicated paths", exclusions)
	}
	if exclusions[0].Path != directory || !exclusions[0].IsDirectory {
		t.Fatalf("first exclusion = %#v, want directory", exclusions[0])
	}
	if exclusions[1].Path != file || exclusions[1].IsDirectory {
		t.Fatalf("second exclusion = %#v, want file", exclusions[1])
	}
}

func TestValidateUserExclusionsRejectsUnsafeOrMissingPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "relative", path: "relative/path"},
		{name: "root", path: "/"},
		{name: "missing", path: filepath.Join(t.TempDir(), "missing")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateUserExclusions([]string{test.path})
			if err == nil {
				t.Fatalf("validateUserExclusions(%q) returned nil error", test.path)
			}
			if test.name == "missing" && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing-path error = %v, want os.ErrNotExist", err)
			}
		})
	}
}

func TestDiscoverDatalessICloudPathsStopsForCanceledContext(t *testing.T) {
	parentContext, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := discoverDatalessICloudPaths(parentContext, t.TempDir())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("discoverDatalessICloudPaths error = %v, want context.Canceled", err)
	}
}

func TestSyftExclusionsScanHomesButSkipOneDriveAndDatalessICloud(t *testing.T) {
	exclusions, err := syftExclusions("/Users/example/Documents/Security/MacScope", []datalessPath{
		{Path: "/Users/example/Library/Mobile Documents/com~apple~CloudDocs/cloud-only.json", IsDirectory: false},
		{Path: "/Users/example/Library/Mobile Documents/com~apple~CloudDocs/cloud-only", IsDirectory: true},
	}, []userPathExclusion{
		{Path: "/Users/example/Downloads", IsDirectory: true},
		{Path: "/Users/example/example.zip", IsDirectory: false},
	})
	if err != nil {
		t.Fatalf("syftExclusions returned an error: %v", err)
	}
	wanted := []string{
		"./Users/*/Library/CloudStorage/OneDrive*",
		"./Users/*/OneDrive*",
		"./Users/example/Library/Mobile Documents/com~apple~CloudDocs/cloud-only.json",
		"./Users/example/Library/Mobile Documents/com~apple~CloudDocs/cloud-only/**",
		"./Users/example/Downloads/**",
		"./Users/example/example.zip",
	}
	for _, pattern := range wanted {
		if !slices.Contains(exclusions, pattern) {
			t.Fatalf("exclusions do not contain %q: %#v", pattern, exclusions)
		}
	}
	if slices.Contains(exclusions, "./Users/**") {
		t.Fatalf("exclusions contain the former all-home exclusion: %#v", exclusions)
	}
}

func TestBuildSyftRuntimeConfigPreservesBaseAndAddsExclusions(t *testing.T) {
	config, err := buildSyftRuntimeConfig([]byte("check-for-app-update: false\n"), []string{"./Users/*/OneDrive*/**", "./Users/example/iCloud local/**"})
	if err != nil {
		t.Fatalf("buildSyftRuntimeConfig returned an error: %v", err)
	}
	want := "check-for-app-update: false\nexclude:\n  - \"./Users/*/OneDrive*/**\"\n  - \"./Users/example/iCloud local/**\"\n"
	if string(config) != want {
		t.Fatalf("runtime config = %q, want %q", string(config), want)
	}
}

func TestParseVersionDocumentRequiresPinnedApplicationAndPlatform(t *testing.T) {
	version, commit, err := parseVersionDocument([]byte(`{
  "application": "syft",
  "gitCommit": "16223e6dd7893fe578787658ceb876257483d404",
  "platform": "darwin/arm64",
  "version": "1.50.0",
  "extra": "ignored"
}`), SyftToolID)
	if err != nil {
		t.Fatalf("parseVersionDocument returned an error: %v", err)
	}
	if version != SyftExpectedVersion || commit != SyftExpectedCommit {
		t.Fatalf("version/commit = %q/%q, want %q/%q", version, commit, SyftExpectedVersion, SyftExpectedCommit)
	}
}

func TestParseSyftDocumentAcceptsCleanRootRelativeLocations(t *testing.T) {
	summary, err := parseSyftDocument([]byte(`{
  "artifacts": [{
    "id": "package-1",
    "name": "example",
    "version": "1.2.3",
    "type": "npm",
    "locations": [{"path": "Applications/Example.app/Contents/package.json", "accessPath": "/Applications/Example.app/Contents/package.json"}],
    "purl": "pkg:npm/example@1.2.3"
  }],
  "source": {"name": "macOS-startup-volume", "type": "directory"},
  "descriptor": {"name": "syft", "version": "1.50.0"},
  "schema": {"version": "16.1.10", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.10.json"}
}`))
	if err != nil {
		t.Fatalf("parseSyftDocument returned an error: %v", err)
	}
	if summary.PackageCount != 1 || summary.SchemaVersion != "16.1.10" {
		t.Fatalf("summary = %#v, want one package with schema 16.1.10", summary)
	}
}

func TestParseSyftDocumentRejectsTraversalLocation(t *testing.T) {
	_, err := parseSyftDocument([]byte(`{
  "artifacts": [{
    "id": "package-1",
    "name": "example",
    "version": "1.2.3",
    "type": "npm",
    "locations": [{"path": "../outside", "accessPath": "../outside"}]
  }],
  "source": {"name": "macOS-startup-volume", "type": "directory"},
  "descriptor": {"name": "syft", "version": "1.50.0"},
  "schema": {"version": "16.1.10", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.10.json"}
}`))
	if err == nil || !strings.Contains(err.Error(), "remain within the root scan source") {
		t.Fatalf("error = %v, want traversal validation error", err)
	}
}

func TestBuildVulnerabilityFindingNormalizesPathAndCPEConfidence(t *testing.T) {
	observedAt := time.Date(2026, 8, 9, 20, 0, 0, 0, time.UTC)
	database := DatabaseIdentity{SchemaVersion: "v6.1.9"}
	match := grypeMatch{
		Vulnerability: grypeVulnerability{
			ID:          "CVE-2026-12345",
			DataSource:  "https://github.com/advisories/GHSA-1234-5678-9abc",
			Namespace:   "nvd:cpe",
			Severity:    "High",
			URLs:        []string{"https://nvd.nist.gov/vuln/detail/CVE-2026-12345"},
			Description: "Example advisory",
			CVSS:        []grypeCVSS{{Version: "3.1", Metrics: grypeCVSSMetric{BaseScore: 8.1}}},
			EPSS:        []grypeEPSS{{CVE: "CVE-2026-12345", EPSS: 0.42}},
			Fix:         grypeFix{Versions: []string{"2.0.0"}, State: "fixed"},
		},
		MatchDetails: []grypeMatchDetail{{Type: "cpe-match", Matcher: "stock-matcher"}},
		Artifact: grypeArtifact{
			ID:        "artifact-1",
			Name:      "example",
			Version:   "1.0.0",
			Type:      "binary",
			Locations: []packageLocation{{Path: "Applications/Example.app/Contents/MacOS/example"}},
			PURL:      "pkg:generic/example@1.0.0",
		},
	}
	finding, err := buildVulnerabilityFinding(match, database, observedAt)
	if err != nil {
		t.Fatalf("buildVulnerabilityFinding returned an error: %v", err)
	}
	if finding.Severity != model.SeverityHigh || finding.Confidence != model.ConfidenceMedium {
		t.Fatalf("severity/confidence = %q/%q, want high/medium", finding.Severity, finding.Confidence)
	}
	if finding.AffectedComponents[0].Path != "/Applications/Example.app/Contents/MacOS/example" {
		t.Fatalf("affected path = %q, want normalized absolute path", finding.AffectedComponents[0].Path)
	}
	if finding.Vulnerabilities[0].CVSS == nil || *finding.Vulnerabilities[0].CVSS != 8.1 {
		t.Fatalf("CVSS = %#v, want 8.1", finding.Vulnerabilities[0].CVSS)
	}
	if finding.Vulnerabilities[0].EPSS == nil || *finding.Vulnerabilities[0].EPSS != 0.42 {
		t.Fatalf("EPSS = %#v, want 0.42", finding.Vulnerabilities[0].EPSS)
	}
}

func TestDeduplicateGrypeMatchesMergesDatabaseNamespaces(t *testing.T) {
	artifact := grypeArtifact{
		ID:        "artifact-1",
		Name:      "example",
		Version:   "1.0.0",
		Type:      "go-module",
		Locations: []packageLocation{{Path: "Applications/Example.app/Contents/MacOS/example"}},
	}
	matches := []grypeMatch{
		{
			Vulnerability: grypeVulnerability{
				ID:         "CVE-2026-12345",
				DataSource: "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
				Namespace:  "nvd:language:go",
				Severity:   "Medium",
				CVSS:       []grypeCVSS{{Version: "3.1", Metrics: grypeCVSSMetric{BaseScore: 6.5}}},
				Fix:        grypeFix{Versions: []string{"1.1.0"}, State: "fixed"},
			},
			MatchDetails: []grypeMatchDetail{{Type: "exact-direct-match", Matcher: "go-module-matcher"}},
			Artifact:     artifact,
		},
		{
			Vulnerability: grypeVulnerability{
				ID:         "CVE-2026-12345",
				DataSource: "https://github.com/advisories/GHSA-1234-5678-9abc",
				Namespace:  "github:language:go",
				Severity:   "High",
				EPSS:       []grypeEPSS{{CVE: "CVE-2026-12345", EPSS: 0.2}},
				Fix:        grypeFix{Versions: []string{"1.1.0"}, State: "fixed"},
			},
			MatchDetails: []grypeMatchDetail{{Type: "exact-direct-match", Matcher: "go-module-matcher"}},
			Artifact:     artifact,
		},
	}
	deduplicated, err := deduplicateGrypeMatches(matches)
	if err != nil {
		t.Fatalf("deduplicateGrypeMatches returned an error: %v", err)
	}
	if len(deduplicated) != 1 {
		t.Fatalf("deduplicated count = %d, want 1", len(deduplicated))
	}
	if deduplicated[0].Vulnerability.Severity != "High" {
		t.Fatalf("merged severity = %q, want High", deduplicated[0].Vulnerability.Severity)
	}
	if len(deduplicated[0].Vulnerability.URLs) != 1 || deduplicated[0].Vulnerability.URLs[0] != "https://github.com/advisories/GHSA-1234-5678-9abc" {
		t.Fatalf("merged URLs = %#v, want GitHub advisory source", deduplicated[0].Vulnerability.URLs)
	}
}
