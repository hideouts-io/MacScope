package sofa

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"macscope/internal/model"
)

func TestBuildCollectionReportsNewerCVEsKEVAndXProtectPosture(t *testing.T) {
	completedAt := time.Date(2026, time.August, 9, 20, 0, 0, 0, time.UTC)
	feed := validTestFeed(completedAt.Add(-time.Hour))
	feed.OSVersions[0].Latest = testRelease("26.6", "25G72", completedAt.Add(-24*time.Hour), map[string]CVEMetadata{
		"CVE-2026-65400": {
			NISTURL:           "https://nvd.nist.gov/vuln/detail/CVE-2026-65400",
			ActivelyExploited: true,
			InKEV:             true,
			Severity:          "Critical",
		},
	})
	feed.OSVersions[0].SecurityReleases = []SecurityRelease{
		feed.OSVersions[0].Latest,
		testRelease("26.4", "25E246", completedAt.Add(-30*24*time.Hour), map[string]CVEMetadata{}),
	}
	body := encodeTestFeed(t, feed)
	collection, err := BuildCollection(FetchResponse{
		SourceURL:   FeedURL,
		StartedAt:   completedAt.Add(-time.Second),
		CompletedAt: completedAt,
		Body:        body,
	}, LocalState{
		MacOSVersion:          "26.4",
		MacOSBuild:            "25E246",
		XProtectConfigVersion: "99",
		XProtectVersion:       "49",
		XProtectPluginVersion: "24",
	})
	if err != nil {
		t.Fatalf("BuildCollection returned an error: %v", err)
	}
	if len(collection.Tools) != 1 || collection.Tools[0].ID != "sofa" || collection.Tools[0].Data == nil {
		t.Fatalf("tools = %#v, want one SOFA feed tool with data provenance", collection.Tools)
	}
	if len(collection.Findings) != 2 {
		t.Fatalf("finding count = %d, want macOS and XProtect findings", len(collection.Findings))
	}
	osFinding := collection.Findings[0]
	if osFinding.Category != model.FindingCategoryOSVulnerability || osFinding.Severity != model.SeverityCritical {
		t.Fatalf("OS finding category/severity = %q/%q, want os_vulnerability/critical", osFinding.Category, osFinding.Severity)
	}
	if len(osFinding.Vulnerabilities) != 1 || !osFinding.Vulnerabilities[0].KnownExploited {
		t.Fatalf("OS vulnerabilities = %#v, want one known-exploited CVE", osFinding.Vulnerabilities)
	}
	if collection.Findings[1].ID != "finding.sofa.xprotect-update" {
		t.Fatalf("second finding ID = %q, want XProtect update finding", collection.Findings[1].ID)
	}
	if len(collection.Artifacts) != 1 || string(collection.Artifacts[0].Content) != string(body) {
		t.Fatal("raw SOFA response was not preserved exactly")
	}
	for _, coverage := range collection.Coverage {
		if coverage.Status != model.CoverageStatusComplete {
			t.Fatalf("coverage %q status = %q, want complete", coverage.ID, coverage.Status)
		}
	}
}

func TestBuildCollectionDoesNotInferExposureWithoutExactBuildMatch(t *testing.T) {
	completedAt := time.Date(2026, time.August, 9, 20, 0, 0, 0, time.UTC)
	feed := validTestFeed(completedAt.Add(-time.Hour))
	body := encodeTestFeed(t, feed)
	collection, err := BuildCollection(FetchResponse{
		SourceURL:   FeedURL,
		StartedAt:   completedAt.Add(-time.Second),
		CompletedAt: completedAt,
		Body:        body,
	}, LocalState{
		MacOSVersion:          "26.6",
		MacOSBuild:            "unexpected-build",
		XProtectConfigVersion: "100",
		XProtectVersion:       "50",
		XProtectPluginVersion: "25",
	})
	if err != nil {
		t.Fatalf("BuildCollection returned an error: %v", err)
	}
	if collection.Coverage[0].Status != model.CoverageStatusPartial {
		t.Fatalf("macOS coverage = %q, want partial", collection.Coverage[0].Status)
	}
	if len(collection.Findings) != 1 || collection.Findings[0].Category != model.FindingCategoryCoverageGap {
		t.Fatalf("findings = %#v, want one coverage-gap finding", collection.Findings)
	}
	if len(collection.Findings[0].Vulnerabilities) != 0 {
		t.Fatalf("coverage-gap vulnerabilities = %#v, want none", collection.Findings[0].Vulnerabilities)
	}
}

func TestDecodeAndValidateFeedRequiresCVEObject(t *testing.T) {
	completedAt := time.Date(2026, time.August, 9, 20, 0, 0, 0, time.UTC)
	feed := validTestFeed(completedAt.Add(-time.Hour))
	feed.OSVersions[0].SecurityReleases[0].CVEs = nil
	body := encodeTestFeed(t, feed)
	_, err := decodeAndValidateFeed(body)
	if err == nil {
		t.Fatal("decodeAndValidateFeed returned nil error for null CVEs")
	}
	if !strings.Contains(err.Error(), "SecurityReleases[0].CVEs") {
		t.Fatalf("error = %q, want CVEs path", err)
	}
}

func validTestFeed(lastCheck time.Time) Feed {
	latest := testRelease("26.6", "25G72", lastCheck.Add(-time.Hour), map[string]CVEMetadata{})
	return Feed{
		Version:       "2.0",
		SchemaVersion: "2026.04.11.2",
		LastCheck:     lastCheck,
		UpdateHash:    strings.Repeat("a", 64),
		OSVersions: []OSVersion{
			{OSVersion: "Tahoe 26", Latest: latest, SecurityReleases: []SecurityRelease{latest}},
		},
		XProtectPayloads: XProtectPayloads{
			FrameworkVersion: "50",
			PluginVersion:    "25",
			ReleaseDate:      lastCheck.Add(-time.Hour),
		},
		XProtectPlistConfigData: XProtectConfigData{
			Version:     "100",
			ReleaseDate: lastCheck.Add(-time.Hour),
		},
	}
}

func testRelease(productVersion string, build string, releaseDate time.Time, cves map[string]CVEMetadata) SecurityRelease {
	return SecurityRelease{
		UpdateName:            "macOS " + productVersion,
		ProductName:           "macOS",
		ProductVersion:        productVersion,
		Build:                 build,
		AllBuilds:             []string{build},
		ReleaseDate:           releaseDate,
		SecurityInfo:          "https://support.apple.com/en-us/100001",
		CVEs:                  cves,
		ActivelyExploitedCVEs: make([]string, 0),
		UpdateSummary: UpdateSummary{
			Priority:       "high",
			Summary:        "Security fixes available",
			Recommendation: "Update",
		},
	}
}

func encodeTestFeed(t *testing.T, feed Feed) []byte {
	t.Helper()
	body, err := json.Marshal(feed)
	if err != nil {
		t.Fatalf("encode test feed: %v", err)
	}
	return body
}
