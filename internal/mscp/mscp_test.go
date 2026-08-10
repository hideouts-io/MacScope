package mscp

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
)

func TestRulesAreUniqueAndReturnedByValue(t *testing.T) {
	rules := Rules()
	if len(rules) != 4 {
		t.Fatalf("rule count = %d, want 4", len(rules))
	}
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if _, exists := seen[rule.ID]; exists {
			t.Fatalf("duplicate rule ID %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if rule.SQL == "" || len(rule.ExpectedValues) == 0 || len(rule.SourceSHA256) != 64 {
			t.Fatalf("incomplete rule %#v", rule)
		}
	}
	rules[0].ExpectedValues[0] = "changed"
	if Rules()[0].ExpectedValues[0] == "changed" {
		t.Fatal("Rules returned shared mutable expected values")
	}
}

func TestManifestArtifactRecordsPinnedSubsetProvenance(t *testing.T) {
	record, reference, err := ManifestArtifact()
	if err != nil {
		t.Fatalf("ManifestArtifact returned an error: %v", err)
	}
	actualDigest := fmt.Sprintf("%x", sha256.Sum256(record.Content))
	if actualDigest != reference.SHA256 {
		t.Fatalf("manifest SHA-256 = %s, reference = %s", actualDigest, reference.SHA256)
	}
	var manifest Manifest
	if err := json.Unmarshal(record.Content, &manifest); err != nil {
		t.Fatalf("decode manifest artifact: %v", err)
	}
	if manifest.Source.CommitSHA != CommitSHA || manifest.Source.ArchiveSHA256 != ArchiveSHA256 {
		t.Fatalf("source identity = %#v, want pinned commit and archive", manifest.Source)
	}
	if manifest.Baseline.RuleCount != BaselineRuleCount || len(manifest.Rules) != 4 {
		t.Fatalf("baseline/rules = %#v/%d, want %d/4", manifest.Baseline, len(manifest.Rules), BaselineRuleCount)
	}
}
