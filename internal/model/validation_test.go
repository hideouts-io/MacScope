package model

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidateScanRunAcceptsCompleteDocument(t *testing.T) {
	run := validScanRun()
	if err := ValidateScanRun(run); err != nil {
		t.Fatalf("ValidateScanRun returned an error: %v", err)
	}
}

func TestEncodeAndDecodeScanRun(t *testing.T) {
	run := validScanRun()
	var encoded bytes.Buffer
	if err := EncodeScanRun(&encoded, run); err != nil {
		t.Fatalf("EncodeScanRun returned an error: %v", err)
	}

	decoded, err := DecodeScanRun(&encoded)
	if err != nil {
		t.Fatalf("DecodeScanRun returned an error: %v", err)
	}
	if decoded.RunID != run.RunID {
		t.Fatalf("decoded run ID = %q, want %q", decoded.RunID, run.RunID)
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0].ID != run.Findings[0].ID {
		t.Fatalf("decoded findings = %#v, want finding ID %q", decoded.Findings, run.Findings[0].ID)
	}
}

func TestDecodeScanRunRejectsUnknownField(t *testing.T) {
	run := validScanRun()
	var encoded bytes.Buffer
	if err := EncodeScanRun(&encoded, run); err != nil {
		t.Fatalf("EncodeScanRun returned an error: %v", err)
	}

	invalidDocument := strings.Replace(encoded.String(), `"schema_version": "1"`, `"schema_version": "1", "unexpected": true`, 1)
	_, err := DecodeScanRun(strings.NewReader(invalidDocument))
	if err == nil {
		t.Fatal("DecodeScanRun returned nil error, want DecodeError")
	}
	var decodeError DecodeError
	if !errors.As(err, &decodeError) {
		t.Fatalf("error type = %T, want DecodeError", err)
	}
}

func TestValidateScanRunRejectsDuplicateEvidenceID(t *testing.T) {
	run := validScanRun()
	run.Evidence = append(run.Evidence, run.Evidence[0])
	assertValidationPath(t, run, "evidence[1].id")
}

func TestValidateScanRunRejectsUnknownEvidenceReference(t *testing.T) {
	run := validScanRun()
	run.Findings[0].EvidenceIDs = []string{"evidence.missing"}
	assertValidationPath(t, run, "findings[0].evidence_ids[0]")
}

func TestValidateScanRunRejectsUnknownToolReference(t *testing.T) {
	run := validScanRun()
	run.Coverage[0].CollectorID = "collector.missing"
	assertValidationPath(t, run, "coverage[0].collector_id")
}

func TestValidateScanRunRejectsArtifactTraversal(t *testing.T) {
	run := validScanRun()
	run.Evidence[0].Artifact = &ArtifactReference{
		Path:      "../outside.json",
		SHA256:    strings.Repeat("b", 64),
		MediaType: "application/json",
	}
	assertValidationPath(t, run, "evidence[0].artifact.path")
}

func TestValidateScanRunRequiresCVEForVulnerabilityFinding(t *testing.T) {
	run := validScanRun()
	run.Findings[0].Category = FindingCategoryOSVulnerability
	assertValidationPath(t, run, "findings[0].vulnerabilities")
}

func TestValidateScanRunRejectsOutOfRangeCVSS(t *testing.T) {
	run := validScanRun()
	invalidCVSS := 10.1
	run.Findings[0].Category = FindingCategorySoftwareVulnerability
	run.Findings[0].Vulnerabilities = []VulnerabilityReference{
		{
			ID:             "CVE-2026-12345",
			Namespace:      VulnerabilityNamespaceCVE,
			CVSS:           &invalidCVSS,
			EPSS:           nil,
			KnownExploited: false,
			URL:            "https://www.cve.org/CVERecord?id=CVE-2026-12345",
		},
	}
	assertValidationPath(t, run, "findings[0].vulnerabilities[0].cvss")
}

func TestValidateScanRunAcceptsGHSAReference(t *testing.T) {
	run := validScanRun()
	run.Findings[0].Category = FindingCategorySoftwareVulnerability
	run.Findings[0].Vulnerabilities = []VulnerabilityReference{
		{
			ID:             "GHSA-abcd-1234-wxyz",
			Namespace:      VulnerabilityNamespaceGHSA,
			CVSS:           nil,
			EPSS:           nil,
			KnownExploited: false,
			URL:            "https://github.com/advisories/GHSA-abcd-1234-wxyz",
		},
	}
	if err := ValidateScanRun(run); err != nil {
		t.Fatalf("ValidateScanRun returned an error for GHSA reference: %v", err)
	}
}

func TestValidateScanRunRejectsKEVOnNonCVEReference(t *testing.T) {
	run := validScanRun()
	run.Findings[0].Category = FindingCategorySoftwareVulnerability
	run.Findings[0].Vulnerabilities = []VulnerabilityReference{
		{
			ID:             "GHSA-abcd-1234-wxyz",
			Namespace:      VulnerabilityNamespaceGHSA,
			CVSS:           nil,
			EPSS:           nil,
			KnownExploited: true,
			URL:            "https://github.com/advisories/GHSA-abcd-1234-wxyz",
		},
	}
	assertValidationPath(t, run, "findings[0].vulnerabilities[0].known_exploited")
}

func TestValidateScanRunRejectsNullVulnerabilityArray(t *testing.T) {
	run := validScanRun()
	run.Findings[0].Vulnerabilities = nil
	assertValidationPath(t, run, "findings[0].vulnerabilities")
}

func TestValidateScanRunRejectsInvalidPrivilegeEvidence(t *testing.T) {
	run := validScanRun()
	collectorUID := 501
	run.Privilege = PrivilegeEvidence{
		Requested:                true,
		Granted:                  true,
		Collector:                "native-privileged",
		OrchestratorEffectiveUID: 501,
		CollectorEffectiveUID:    &collectorUID,
	}
	assertValidationPath(t, run, "privilege.collector_effective_uid")
}

func TestValidateScanRunRejectsCollectorOutsideRunInterval(t *testing.T) {
	run := validScanRun()
	run.Coverage[0].CompletedAt = run.CompletedAt.Add(time.Second)
	assertValidationPath(t, run, "coverage[0]")
}

func TestValidateScanRunRejectsNullTopLevelArray(t *testing.T) {
	run := validScanRun()
	run.Findings = nil
	assertValidationPath(t, run, "findings")
}

func assertValidationPath(t *testing.T, run ScanRun, expectedPath string) {
	t.Helper()
	err := ValidateScanRun(run)
	if err == nil {
		t.Fatalf("ValidateScanRun returned nil error, want ValidationError at %s", expectedPath)
	}
	var validationError ValidationError
	if !errors.As(err, &validationError) {
		t.Fatalf("error type = %T, want ValidationError", err)
	}
	if validationError.Path != expectedPath {
		t.Fatalf("validation path = %q, want %q; message: %s", validationError.Path, expectedPath, validationError.Message)
	}
}

func validScanRun() ScanRun {
	startedAt := time.Date(2026, time.August, 9, 10, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Minute)
	observedAt := startedAt.Add(10 * time.Second)
	return ScanRun{
		SchemaVersion: ScanSchemaVersion,
		RunID:         "019fe5f1-6b09-4b00-869b-3af5e4e231f4",
		Scanner: ScannerIdentity{
			Name:    "MacScope",
			Version: "0.1.0-dev",
		},
		Host: HostIdentity{
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
		Status:      RunStatusCompleted,
		Privilege: PrivilegeEvidence{
			Requested:                false,
			Granted:                  false,
			Collector:                "none",
			OrchestratorEffectiveUID: 501,
			CollectorEffectiveUID:    nil,
		},
		Tools: []ToolRecord{
			{
				ID:      "macscope",
				Name:    "MacScope",
				Version: "0.1.0-dev",
				Kind:    ToolKindScanner,
				Origin:  "https://github.com/example/macscope",
				Executable: &ExecutableIdentity{
					Path:   "/Applications/MacScope.app/Contents/MacOS/macscope",
					SHA256: strings.Repeat("a", 64),
				},
				Data: nil,
			},
		},
		Coverage: []CoverageRecord{
			{
				ID:                "coverage.host-identity",
				CollectorID:       "macscope",
				Area:              CoverageAreaHostIdentity,
				Target:            "local-mac",
				Status:            CoverageStatusComplete,
				Reason:            "",
				PrivilegeRequired: false,
				StartedAt:         startedAt,
				CompletedAt:       observedAt,
			},
		},
		Evidence: []EvidenceRecord{
			{
				ID:          "evidence.filevault-status",
				CollectorID: "macscope",
				Kind:        EvidenceKindObservation,
				ObservedAt:  observedAt,
				Subject:     "FileVault status",
				Summary:     "FileVault is disabled",
				Command:     nil,
				Artifact:    nil,
			},
		},
		Findings: []Finding{
			{
				ID:              "finding.filevault-disabled",
				Category:        FindingCategoryConfiguration,
				Title:           "FileVault is disabled",
				Description:     "The startup volume is not protected by FileVault full-disk encryption.",
				Severity:        SeverityHigh,
				Confidence:      ConfidenceConfirmed,
				Status:          FindingStatusDetected,
				FirstObservedAt: observedAt,
				Sources: []SourceReference{
					{
						ToolID:      "macscope",
						RuleID:      "native.filevault.enabled",
						RuleVersion: "1",
					},
				},
				EvidenceIDs: []string{"evidence.filevault-status"},
				AffectedComponents: []AffectedComponent{
					{
						Kind:       AffectedComponentConfiguration,
						Identifier: "com.apple.filevault",
						Name:       "FileVault",
						Version:    "",
						Path:       "",
					},
				},
				Vulnerabilities: make([]VulnerabilityReference, 0),
				Remediation: Remediation{
					Summary:         "Enable FileVault for the startup volume.",
					Steps:           []string{"Review recovery-key handling, then enable FileVault in System Settings."},
					RequiresAdmin:   true,
					RequiresRestart: false,
					References:      []string{"https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785/mac"},
				},
			},
		},
	}
}
