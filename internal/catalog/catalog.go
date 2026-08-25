package catalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"macscope/internal/model"
)

//go:embed findings-catalog.json
var documentBytes []byte

type MatchType string

const (
	MatchExact         MatchType = "exact"
	MatchPrefix        MatchType = "prefix"
	MatchVulnerability MatchType = "vulnerability"
)

type Document struct {
	SchemaVersion string  `json:"schema_version"`
	Rules         []Entry `json:"rules"`
}

type Entry struct {
	ID                string                `json:"id"`
	ToolID            string                `json:"tool_id"`
	RuleMatch         MatchType             `json:"rule_match"`
	RuleValue         string                `json:"rule_value"`
	Title             string                `json:"title"`
	Category          model.FindingCategory `json:"category"`
	Explanation       string                `json:"explanation"`
	DetectionLogic    string                `json:"detection_logic"`
	ExpectedState     string                `json:"expected_state"`
	ObservedState     string                `json:"observed_state_interpretation"`
	SeverityRationale string                `json:"severity_rationale"`
	ExpectedEvidence  []string              `json:"expected_evidence"`
	FalsePositives    []string              `json:"possible_false_positives"`
	Limitations       []string              `json:"limitations"`
	Remediation       []string              `json:"remediation"`
	Verification      []string              `json:"verification"`
	References        []string              `json:"references"`
	SupportedMacOS    []string              `json:"supported_macos"`
}

func Load() (Document, error) {
	decoder := json.NewDecoder(strings.NewReader(string(documentBytes)))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("decode embedded findings catalog: %w", err)
	}
	if document.SchemaVersion != "1" {
		return Document{}, fmt.Errorf("validate findings catalog: unsupported schema version %q", document.SchemaVersion)
	}
	if document.Rules == nil || len(document.Rules) == 0 {
		return Document{}, fmt.Errorf("validate findings catalog: rules must not be empty")
	}
	identifiers := make(map[string]struct{}, len(document.Rules))
	for index, entry := range document.Rules {
		if err := validateEntry(entry); err != nil {
			return Document{}, fmt.Errorf("validate findings catalog rule %d: %w", index, err)
		}
		if _, exists := identifiers[entry.ID]; exists {
			return Document{}, fmt.Errorf("validate findings catalog: duplicate ID %q", entry.ID)
		}
		identifiers[entry.ID] = struct{}{}
	}
	return copyDocument(document), nil
}

func Resolve(document Document, toolID string, ruleID string) (Entry, bool) {
	for _, entry := range document.Rules {
		if entry.ToolID == toolID && entry.RuleMatch == MatchExact && entry.RuleValue == ruleID {
			return copyEntry(entry), true
		}
	}
	for _, entry := range document.Rules {
		if entry.ToolID != toolID {
			continue
		}
		if entry.RuleMatch == MatchPrefix && strings.HasPrefix(ruleID, entry.RuleValue) {
			return copyEntry(entry), true
		}
		if entry.RuleMatch == MatchVulnerability && strings.TrimSpace(ruleID) != "" {
			return copyEntry(entry), true
		}
	}
	return Entry{}, false
}

func ValidateFindingSources(document Document, findings []model.Finding) error {
	for _, finding := range findings {
		for _, source := range finding.Sources {
			if _, resolved := Resolve(document, source.ToolID, source.RuleID); !resolved {
				return fmt.Errorf("validate finding %q source %s/%s: no findings catalog rule matches", finding.ID, source.ToolID, source.RuleID)
			}
		}
	}
	return nil
}

func validateEntry(entry Entry) error {
	required := []struct{ name, value string }{
		{"ID", entry.ID}, {"tool ID", entry.ToolID}, {"rule value", entry.RuleValue}, {"title", entry.Title},
		{"explanation", entry.Explanation}, {"detection logic", entry.DetectionLogic}, {"expected state", entry.ExpectedState},
		{"observed-state interpretation", entry.ObservedState}, {"severity rationale", entry.SeverityRationale},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s must not be empty", field.name)
		}
	}
	if entry.RuleMatch != MatchExact && entry.RuleMatch != MatchPrefix && entry.RuleMatch != MatchVulnerability {
		return fmt.Errorf("unsupported rule match %q", entry.RuleMatch)
	}
	for name, values := range map[string][]string{
		"expected evidence": entry.ExpectedEvidence, "possible false positives": entry.FalsePositives, "limitations": entry.Limitations, "remediation": entry.Remediation,
		"verification": entry.Verification, "references": entry.References, "supported macOS": entry.SupportedMacOS,
	} {
		if values == nil || len(values) == 0 {
			return fmt.Errorf("%s must not be empty", name)
		}
	}
	return nil
}

func copyDocument(document Document) Document {
	rules := make([]Entry, len(document.Rules))
	for index, entry := range document.Rules {
		rules[index] = copyEntry(entry)
	}
	return Document{SchemaVersion: document.SchemaVersion, Rules: rules}
}

func copyEntry(entry Entry) Entry {
	copied := entry
	copied.ExpectedEvidence = append([]string(nil), entry.ExpectedEvidence...)
	copied.FalsePositives = append([]string(nil), entry.FalsePositives...)
	copied.Limitations = append([]string(nil), entry.Limitations...)
	copied.Remediation = append([]string(nil), entry.Remediation...)
	copied.Verification = append([]string(nil), entry.Verification...)
	copied.References = append([]string(nil), entry.References...)
	copied.SupportedMacOS = append([]string(nil), entry.SupportedMacOS...)
	return copied
}
