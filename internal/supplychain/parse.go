package supplychain

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

type SyftSummary struct {
	PackageCount  int
	SchemaVersion string
}

type syftDocument struct {
	Artifacts  []syftArtifact `json:"artifacts"`
	Source     syftSource     `json:"source"`
	Descriptor syftDescriptor `json:"descriptor"`
	Schema     syftSchema     `json:"schema"`
}

type syftArtifact struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Type      string            `json:"type"`
	Locations []packageLocation `json:"locations"`
	PURL      string            `json:"purl"`
}

type syftSource struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type syftDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type syftSchema struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

type packageLocation struct {
	Path       string `json:"path"`
	AccessPath string `json:"accessPath"`
}

type DatabaseIdentity struct {
	SchemaVersion string
	Source        string
	BuiltAt       time.Time
	Path          string
	SHA256        string
}

type databaseStatusDocument struct {
	SchemaVersion string    `json:"schemaVersion"`
	Source        string    `json:"from"`
	BuiltAt       time.Time `json:"built"`
	Path          string    `json:"path"`
	Valid         bool      `json:"valid"`
}

type GrypeDocument struct {
	Matches       []grypeMatch    `json:"matches"`
	Source        grypeSource     `json:"source"`
	Descriptor    grypeDescriptor `json:"descriptor"`
	RawMatchCount int             `json:"-"`
}

type grypeSource struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

type grypeDescriptor struct {
	Name    string                  `json:"name"`
	Version string                  `json:"version"`
	DB      grypeDatabaseDescriptor `json:"db"`
}

type grypeDatabaseDescriptor struct {
	Status databaseStatusDocument `json:"status"`
}

type grypeMatch struct {
	Vulnerability grypeVulnerability `json:"vulnerability"`
	MatchDetails  []grypeMatchDetail `json:"matchDetails"`
	Artifact      grypeArtifact      `json:"artifact"`
}

type grypeVulnerability struct {
	ID          string      `json:"id"`
	DataSource  string      `json:"dataSource"`
	Namespace   string      `json:"namespace"`
	Severity    string      `json:"severity"`
	URLs        []string    `json:"urls"`
	Description string      `json:"description"`
	CVSS        []grypeCVSS `json:"cvss"`
	EPSS        []grypeEPSS `json:"epss"`
	Fix         grypeFix    `json:"fix"`
}

type grypeCVSS struct {
	Version string          `json:"version"`
	Metrics grypeCVSSMetric `json:"metrics"`
}

type grypeCVSSMetric struct {
	BaseScore float64 `json:"baseScore"`
}

type grypeEPSS struct {
	CVE  string  `json:"cve"`
	EPSS float64 `json:"epss"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type grypeMatchDetail struct {
	Type    string `json:"type"`
	Matcher string `json:"matcher"`
}

type grypeArtifact struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Type      string            `json:"type"`
	Locations []packageLocation `json:"locations"`
	PURL      string            `json:"purl"`
}

func parseSyftDocument(output []byte) (SyftSummary, error) {
	var document syftDocument
	if err := json.Unmarshal(output, &document); err != nil {
		return SyftSummary{}, fmt.Errorf("decode Syft JSON: %w", err)
	}
	if document.Artifacts == nil {
		return SyftSummary{}, fmt.Errorf("validate Syft JSON: artifacts array must not be null")
	}
	if document.Descriptor.Name != SyftToolID || document.Descriptor.Version != SyftExpectedVersion {
		return SyftSummary{}, fmt.Errorf("validate Syft JSON: descriptor name/version %q/%q does not match %q/%q", document.Descriptor.Name, document.Descriptor.Version, SyftToolID, SyftExpectedVersion)
	}
	if document.Source.Type != "directory" || document.Source.Name != "macOS-startup-volume" {
		return SyftSummary{}, fmt.Errorf("validate Syft JSON: source type/name %q/%q does not match named directory root target", document.Source.Type, document.Source.Name)
	}
	if strings.TrimSpace(document.Schema.Version) == "" {
		return SyftSummary{}, fmt.Errorf("validate Syft JSON: schema version is required")
	}
	if err := requireHTTPSURL("Syft schema URL", document.Schema.URL); err != nil {
		return SyftSummary{}, err
	}
	seenArtifacts := make(map[string]struct{}, len(document.Artifacts))
	for index, item := range document.Artifacts {
		if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Version) == "" || strings.TrimSpace(item.Type) == "" {
			return SyftSummary{}, fmt.Errorf("validate Syft JSON artifact %d: id, name, version, and type are required", index)
		}
		if _, exists := seenArtifacts[item.ID]; exists {
			return SyftSummary{}, fmt.Errorf("validate Syft JSON artifact %d: duplicate artifact ID %q", index, item.ID)
		}
		seenArtifacts[item.ID] = struct{}{}
		if item.Locations == nil {
			return SyftSummary{}, fmt.Errorf("validate Syft JSON artifact %d: locations array must not be null", index)
		}
		for locationIndex, location := range item.Locations {
			if err := validateRootLocation(location.Path); err != nil {
				return SyftSummary{}, fmt.Errorf("validate Syft JSON artifact %d location %d: %w", index, locationIndex, err)
			}
		}
	}
	return SyftSummary{PackageCount: len(document.Artifacts), SchemaVersion: document.Schema.Version}, nil
}

func parseDatabaseStatus(output []byte, databaseDirectory string) (DatabaseIdentity, error) {
	var document databaseStatusDocument
	if err := json.Unmarshal(output, &document); err != nil {
		return DatabaseIdentity{}, fmt.Errorf("decode Grype database status JSON: %w", err)
	}
	if strings.TrimSpace(document.SchemaVersion) == "" {
		return DatabaseIdentity{}, fmt.Errorf("validate Grype database status: schemaVersion is required")
	}
	if err := requireHTTPSURL("Grype database source", document.Source); err != nil {
		return DatabaseIdentity{}, err
	}
	if document.BuiltAt.IsZero() {
		return DatabaseIdentity{}, fmt.Errorf("validate Grype database status: built timestamp is required")
	}
	if !document.Valid {
		return DatabaseIdentity{}, fmt.Errorf("validate Grype database status: database reports valid=false")
	}
	if !filepath.IsAbs(document.Path) {
		return DatabaseIdentity{}, fmt.Errorf("validate Grype database status: path %q must be absolute", document.Path)
	}
	relativePath, err := filepath.Rel(databaseDirectory, document.Path)
	if err != nil {
		return DatabaseIdentity{}, fmt.Errorf("validate Grype database status path %q against cache %q: %w", document.Path, databaseDirectory, err)
	}
	if relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return DatabaseIdentity{}, fmt.Errorf("validate Grype database status: path %q is outside configured cache %q", document.Path, databaseDirectory)
	}
	digest, err := hashFile(document.Path)
	if err != nil {
		return DatabaseIdentity{}, fmt.Errorf("hash Grype vulnerability database %q: %w", document.Path, err)
	}
	return DatabaseIdentity{
		SchemaVersion: document.SchemaVersion,
		Source:        document.Source,
		BuiltAt:       document.BuiltAt.UTC(),
		Path:          document.Path,
		SHA256:        digest,
	}, nil
}

func parseGrypeDocument(output []byte, database DatabaseIdentity) (GrypeDocument, error) {
	var document GrypeDocument
	if err := json.Unmarshal(output, &document); err != nil {
		return GrypeDocument{}, fmt.Errorf("decode Grype JSON: %w", err)
	}
	if document.Matches == nil {
		return GrypeDocument{}, fmt.Errorf("validate Grype JSON: matches array must not be null")
	}
	if document.Descriptor.Name != GrypeToolID || document.Descriptor.Version != GrypeExpectedVersion {
		return GrypeDocument{}, fmt.Errorf("validate Grype JSON: descriptor name/version %q/%q does not match %q/%q", document.Descriptor.Name, document.Descriptor.Version, GrypeToolID, GrypeExpectedVersion)
	}
	if document.Source.Type != "directory" || document.Source.Target != "/" {
		return GrypeDocument{}, fmt.Errorf("validate Grype JSON: source type/target %q/%q does not match Syft root SBOM path", document.Source.Type, document.Source.Target)
	}
	if err := validateReportDatabase(document.Descriptor.DB.Status, database); err != nil {
		return GrypeDocument{}, err
	}
	for index, match := range document.Matches {
		if strings.TrimSpace(match.Vulnerability.ID) == "" || strings.TrimSpace(match.Vulnerability.Severity) == "" || strings.TrimSpace(match.Vulnerability.Namespace) == "" {
			return GrypeDocument{}, fmt.Errorf("validate Grype JSON match %d: vulnerability id, namespace, and severity are required", index)
		}
		if strings.TrimSpace(match.Artifact.ID) == "" || strings.TrimSpace(match.Artifact.Name) == "" || strings.TrimSpace(match.Artifact.Version) == "" || strings.TrimSpace(match.Artifact.Type) == "" {
			return GrypeDocument{}, fmt.Errorf("validate Grype JSON match %d: artifact id, name, version, and type are required", index)
		}
		if len(match.MatchDetails) == 0 {
			return GrypeDocument{}, fmt.Errorf("validate Grype JSON match %d: at least one match detail is required", index)
		}
		for locationIndex, location := range match.Artifact.Locations {
			if err := validateRootLocation(location.Path); err != nil {
				return GrypeDocument{}, fmt.Errorf("validate Grype JSON match %d location %d: %w", index, locationIndex, err)
			}
		}
	}
	document.RawMatchCount = len(document.Matches)
	deduplicated, err := deduplicateGrypeMatches(document.Matches)
	if err != nil {
		return GrypeDocument{}, err
	}
	document.Matches = deduplicated
	return document, nil
}

func deduplicateGrypeMatches(matches []grypeMatch) ([]grypeMatch, error) {
	result := make([]grypeMatch, 0, len(matches))
	indexes := make(map[string]int, len(matches))
	for _, match := range matches {
		identity := match.Vulnerability.ID + "\x00" + match.Artifact.ID
		index, exists := indexes[identity]
		if !exists {
			indexes[identity] = len(result)
			result = append(result, copyGrypeMatch(match))
			continue
		}
		merged, err := mergeGrypeMatches(result[index], match)
		if err != nil {
			return nil, fmt.Errorf("merge duplicate Grype vulnerability/artifact identity %q/%q: %w", match.Vulnerability.ID, match.Artifact.ID, err)
		}
		result[index] = merged
	}
	return result, nil
}

func mergeGrypeMatches(first grypeMatch, second grypeMatch) (grypeMatch, error) {
	if !reflect.DeepEqual(first.Artifact, second.Artifact) {
		return grypeMatch{}, fmt.Errorf("artifact details differ for shared artifact ID %q", first.Artifact.ID)
	}
	if first.Vulnerability.Fix.State != "" && second.Vulnerability.Fix.State != "" && first.Vulnerability.Fix.State != second.Vulnerability.Fix.State {
		return grypeMatch{}, fmt.Errorf("fix states differ: %q and %q", first.Vulnerability.Fix.State, second.Vulnerability.Fix.State)
	}
	merged := copyGrypeMatch(first)
	if grypeSeverityRank(second.Vulnerability.Severity) > grypeSeverityRank(merged.Vulnerability.Severity) {
		merged.Vulnerability.Severity = second.Vulnerability.Severity
	}
	if len(second.Vulnerability.Description) > len(merged.Vulnerability.Description) {
		merged.Vulnerability.Description = second.Vulnerability.Description
	}
	merged.Vulnerability.URLs = uniqueStrings(append(append(merged.Vulnerability.URLs, second.Vulnerability.DataSource), second.Vulnerability.URLs...))
	merged.Vulnerability.CVSS = append(append([]grypeCVSS(nil), merged.Vulnerability.CVSS...), second.Vulnerability.CVSS...)
	merged.Vulnerability.EPSS = append(append([]grypeEPSS(nil), merged.Vulnerability.EPSS...), second.Vulnerability.EPSS...)
	merged.Vulnerability.Fix.Versions = uniqueStrings(append(merged.Vulnerability.Fix.Versions, second.Vulnerability.Fix.Versions...))
	if merged.Vulnerability.Fix.State == "" {
		merged.Vulnerability.Fix.State = second.Vulnerability.Fix.State
	}
	merged.MatchDetails = uniqueMatchDetails(append(merged.MatchDetails, second.MatchDetails...))
	return merged, nil
}

func copyGrypeMatch(match grypeMatch) grypeMatch {
	copied := match
	copied.Vulnerability.URLs = append([]string(nil), match.Vulnerability.URLs...)
	copied.Vulnerability.CVSS = append([]grypeCVSS(nil), match.Vulnerability.CVSS...)
	copied.Vulnerability.EPSS = append([]grypeEPSS(nil), match.Vulnerability.EPSS...)
	copied.Vulnerability.Fix.Versions = append([]string(nil), match.Vulnerability.Fix.Versions...)
	copied.MatchDetails = append([]grypeMatchDetail(nil), match.MatchDetails...)
	copied.Artifact.Locations = append([]packageLocation(nil), match.Artifact.Locations...)
	return copied
}

func grypeSeverityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "unknown":
		return 0
	case "negligible":
		return 1
	case "low":
		return 2
	case "medium", "moderate":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	default:
		return -1
	}
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqueMatchDetails(details []grypeMatchDetail) []grypeMatchDetail {
	result := make([]grypeMatchDetail, 0, len(details))
	seen := make(map[string]struct{}, len(details))
	for _, detail := range details {
		identity := detail.Type + "\x00" + detail.Matcher
		if _, exists := seen[identity]; exists {
			continue
		}
		seen[identity] = struct{}{}
		result = append(result, detail)
	}
	return result
}

func validateRootLocation(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("path must not be empty")
	}
	cleanPath := filepath.Clean(path)
	if cleanPath == "." || cleanPath != path || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q must be clean and remain within the root scan source", path)
	}
	return nil
}

func validateReportDatabase(status databaseStatusDocument, expected DatabaseIdentity) error {
	if !status.Valid {
		return fmt.Errorf("validate Grype JSON database descriptor: valid=false")
	}
	if status.SchemaVersion != expected.SchemaVersion || status.Source != expected.Source || !status.BuiltAt.Equal(expected.BuiltAt) || status.Path != expected.Path {
		return fmt.Errorf("validate Grype JSON database descriptor: report database identity does not match pre-scan status")
	}
	return nil
}

func requireHTTPSURL(name string, value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return fmt.Errorf("validate %s %q: %w", name, value, err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("validate %s %q: URL must use HTTPS and include a host", name, value)
	}
	return nil
}
