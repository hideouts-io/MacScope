package report

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"macscope/internal/model"
)

func TestGenerateWritesEscapedPrioritizedReportAndRefusesOverwrite(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "scan.json")
	outputPath := filepath.Join(directory, "report.html")
	writeTestScan(t, inputPath, testScanRun())

	result, err := Generate(inputPath, outputPath)
	if err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}
	if result.OutputPath != outputPath {
		t.Fatalf("output path = %q, want %q", result.OutputPath, outputPath)
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read generated report: %v", err)
	}
	html := string(content)
	if strings.Contains(html, "<script>alert") || !strings.Contains(html, "&lt;script&gt;alert") {
		t.Fatalf("generated report did not safely escape finding title: %s", html)
	}
	criticalIndex := strings.Index(html, "Critical &lt;script&gt;alert")
	highIndex := strings.Index(html, "High configuration finding")
	if criticalIndex < 0 || highIndex < 0 || criticalIndex >= highIndex {
		t.Fatalf("finding order is not critical before high: critical=%d high=%d", criticalIndex, highIndex)
	}
	if !strings.Contains(html, "EPSS 42.00%") || !strings.Contains(html, "CVSS 9.8") {
		t.Fatalf("generated report does not contain formatted vulnerability scores")
	}
	scanContent, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read source scan: %v", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(scanContent))
	if !strings.Contains(html, digest) {
		t.Fatalf("generated report does not contain source SHA-256 %s", digest)
	}

	_, err = Generate(inputPath, outputPath)
	if err == nil {
		t.Fatal("second Generate returned nil error, want OutputError")
	}
	var outputError OutputError
	if !errors.As(err, &outputError) {
		t.Fatalf("second Generate error type = %T, want OutputError", err)
	}
}

func TestGenerateRejectsInvalidScanWithoutWritingOutput(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "scan.json")
	outputPath := filepath.Join(directory, "report.html")
	if err := os.WriteFile(inputPath, []byte(`{"schema_version":"unsupported"}`), 0o640); err != nil {
		t.Fatalf("write invalid scan: %v", err)
	}
	_, err := Generate(inputPath, outputPath)
	if err == nil {
		t.Fatal("Generate returned nil error, want InputError")
	}
	var inputError InputError
	if !errors.As(err, &inputError) {
		t.Fatalf("Generate error type = %T, want InputError", err)
	}
	if _, statErr := os.Stat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("output stat error = %v, want not-exist", statErr)
	}
}

func writeTestScan(t *testing.T, path string, run model.ScanRun) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		t.Fatalf("create test scan: %v", err)
	}
	if err := model.EncodeScanRun(file, run); err != nil {
		_ = file.Close()
		t.Fatalf("encode test scan: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close test scan: %v", err)
	}
}

func testScanRun() model.ScanRun {
	startedAt := time.Date(2026, time.August, 9, 20, 0, 0, 0, time.UTC)
	observedAt := startedAt.Add(time.Second)
	completedAt := startedAt.Add(time.Minute)
	cvss := 9.8
	epss := 0.42
	baseRemediation := model.Remediation{
		Summary:         "Apply the documented remediation.",
		Steps:           []string{"Review applicability and install the fixed version."},
		RequiresAdmin:   false,
		RequiresRestart: false,
		References:      []string{"https://example.com/remediation"},
	}
	return model.ScanRun{
		SchemaVersion: model.ScanSchemaVersion,
		RunID:         "019fe5f1-6b09-4b00-869b-3af5e4e231f4",
		Scanner:       model.ScannerIdentity{Name: "MacScope", Version: "0.1.0-dev"},
		Host: model.HostIdentity{
			Hostname:     "test-mac",
			OperatingOS:  "darwin",
			Architecture: "arm64",
			MacOSVersion: "26.4",
			MacOSBuild:   "25E246",
			ModelID:      "MacBookPro18,3",
			Chip:         "Apple M3 Max",
		},
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Status:      model.RunStatusPartial,
		Privilege: model.PrivilegeEvidence{
			Requested:                false,
			Granted:                  false,
			Collector:                "none",
			OrchestratorEffectiveUID: 501,
			CollectorEffectiveUID:    nil,
		},
		Tools: []model.ToolRecord{{
			ID:      "macscope",
			Name:    "MacScope",
			Version: "0.1.0-dev",
			Kind:    model.ToolKindScanner,
			Executable: &model.ExecutableIdentity{
				Path:   "/Applications/MacScope.app/Contents/MacOS/macscope",
				SHA256: strings.Repeat("a", 64),
			},
		}},
		Coverage: []model.CoverageRecord{{
			ID:                "coverage.test-partial",
			CollectorID:       "macscope",
			Area:              model.CoverageAreaInstalledSoftware,
			Target:            "test target",
			Status:            model.CoverageStatusPartial,
			Reason:            "test limitation",
			PrivilegeRequired: false,
			StartedAt:         startedAt,
			CompletedAt:       observedAt,
		}},
		Evidence: []model.EvidenceRecord{{
			ID:          "evidence.test-observation",
			CollectorID: "macscope",
			Kind:        model.EvidenceKindObservation,
			ObservedAt:  observedAt,
			Subject:     "test observation",
			Summary:     "validated test evidence",
			Command:     nil,
			Artifact:    nil,
		}},
		Findings: []model.Finding{
			{
				ID:              "finding.high-configuration",
				Category:        model.FindingCategoryConfiguration,
				Title:           "High configuration finding",
				Description:     "A high-severity configuration observation.",
				Severity:        model.SeverityHigh,
				Confidence:      model.ConfidenceConfirmed,
				Status:          model.FindingStatusDetected,
				FirstObservedAt: observedAt,
				Sources:         []model.SourceReference{{ToolID: "macscope", RuleID: "test.high", RuleVersion: "1"}},
				EvidenceIDs:     []string{"evidence.test-observation"},
				AffectedComponents: []model.AffectedComponent{{
					Kind:       model.AffectedComponentConfiguration,
					Identifier: "test.high",
					Name:       "Test setting",
				}},
				Vulnerabilities: make([]model.VulnerabilityReference, 0),
				Remediation:     baseRemediation,
			},
			{
				ID:              "finding.critical-vulnerability",
				Category:        model.FindingCategorySoftwareVulnerability,
				Title:           "Critical <script>alert finding",
				Description:     "A critical package-version match.",
				Severity:        model.SeverityCritical,
				Confidence:      model.ConfidenceHigh,
				Status:          model.FindingStatusDetected,
				FirstObservedAt: observedAt,
				Sources:         []model.SourceReference{{ToolID: "macscope", RuleID: "test.critical", RuleVersion: "1"}},
				EvidenceIDs:     []string{"evidence.test-observation"},
				AffectedComponents: []model.AffectedComponent{{
					Kind:       model.AffectedComponentPackage,
					Identifier: "pkg:generic/example@1.0.0",
					Name:       "example",
					Version:    "1.0.0",
				}},
				Vulnerabilities: []model.VulnerabilityReference{{
					ID:             "CVE-2026-12345",
					Namespace:      model.VulnerabilityNamespaceCVE,
					CVSS:           &cvss,
					EPSS:           &epss,
					KnownExploited: true,
					URL:            "https://example.com/CVE-2026-12345",
				}},
				Remediation: baseRemediation,
			},
		},
	}
}
