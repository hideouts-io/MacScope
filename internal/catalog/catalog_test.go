package catalog

import (
	"testing"

	"macscope/internal/model"
)

func TestEmbeddedCatalogLoadsAndResolvesSupportedRuleFamilies(t *testing.T) {
	document, err := Load()
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	tests := []struct {
		toolID string
		ruleID string
	}{
		{"macscope", "native.filevault"},
		{"sofa", "sofa.macos.release-posture"},
		{"mscp", "os_sip_enable"},
		{"osquery", "query.listening-ports"},
		{"grype", "CVE-2026-1234"},
		{"macscope", "supply-chain.coverage"},
	}
	for _, test := range tests {
		if _, resolved := Resolve(document, test.toolID, test.ruleID); !resolved {
			t.Fatalf("Resolve(%q, %q) = false", test.toolID, test.ruleID)
		}
	}
}

func TestValidateFindingSourcesRejectsUnknownTool(t *testing.T) {
	document, err := Load()
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	findings := []model.Finding{{
		ID:      "finding.test",
		Sources: []model.SourceReference{{ToolID: "unknown", RuleID: "unknown.rule"}},
	}}
	if err := ValidateFindingSources(document, findings); err == nil {
		t.Fatal("ValidateFindingSources returned nil error")
	}
}
