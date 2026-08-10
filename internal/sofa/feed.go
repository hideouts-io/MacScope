package sofa

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"macscope/internal/artifact"
	"macscope/internal/model"
)

var (
	sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	cvePattern    = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

type Feed struct {
	Version                 string             `json:"Version"`
	SchemaVersion           string             `json:"SchemaVersion"`
	LastCheck               time.Time          `json:"LastCheck"`
	UpdateHash              string             `json:"UpdateHash"`
	OSVersions              []OSVersion        `json:"OSVersions"`
	XProtectPayloads        XProtectPayloads   `json:"XProtectPayloads"`
	XProtectPlistConfigData XProtectConfigData `json:"XProtectPlistConfigData"`
}

type OSVersion struct {
	OSVersion        string            `json:"OSVersion"`
	Latest           SecurityRelease   `json:"Latest"`
	SecurityReleases []SecurityRelease `json:"SecurityReleases"`
}

type SecurityRelease struct {
	UpdateName            string                 `json:"UpdateName"`
	ProductName           string                 `json:"ProductName"`
	ProductVersion        string                 `json:"ProductVersion"`
	Build                 string                 `json:"Build"`
	AllBuilds             []string               `json:"AllBuilds"`
	ReleaseDate           time.Time              `json:"ReleaseDate"`
	SecurityInfo          string                 `json:"SecurityInfo"`
	CVEs                  map[string]CVEMetadata `json:"CVEs"`
	ActivelyExploitedCVEs []string               `json:"ActivelyExploitedCVEs"`
	UpdateSummary         UpdateSummary          `json:"UpdateSummary"`
}

type CVEMetadata struct {
	NISTURL           string `json:"NISTURL"`
	ActivelyExploited bool   `json:"ActivelyExploited"`
	InKEV             bool   `json:"InKEV"`
	Severity          string `json:"Severity"`
}

type UpdateSummary struct {
	Priority       string `json:"Priority"`
	Summary        string `json:"Summary"`
	Recommendation string `json:"Recommendation"`
}

type XProtectPayloads struct {
	FrameworkVersion string    `json:"com.apple.XProtectFramework.XProtect"`
	PluginVersion    string    `json:"com.apple.XprotectFramework.PluginService"`
	ReleaseDate      time.Time `json:"ReleaseDate"`
}

type XProtectConfigData struct {
	Version     string    `json:"com.apple.XProtect"`
	ReleaseDate time.Time `json:"ReleaseDate"`
}

type LocalState struct {
	MacOSVersion          string
	MacOSBuild            string
	XProtectConfigVersion string
	XProtectVersion       string
	XProtectPluginVersion string
}

type Collection struct {
	Tools     []model.ToolRecord
	Coverage  []model.CoverageRecord
	Evidence  []model.EvidenceRecord
	Findings  []model.Finding
	Artifacts []artifact.Record
}

type FeedValidationError struct {
	Path    string
	Message string
}

func (err FeedValidationError) Error() string {
	return fmt.Sprintf("validate SOFA feed at %s: %s", err.Path, err.Message)
}

type hostReleaseAssessment struct {
	CoverageStatus model.CoverageStatus
	CoverageReason string
	Finding        *model.Finding
}

type xProtectAssessment struct {
	CoverageStatus model.CoverageStatus
	CoverageReason string
	Finding        *model.Finding
}

type outdatedXProtectComponent struct {
	Identifier       string
	Name             string
	InstalledVersion string
	CurrentVersion   string
	EvidenceID       string
}

func BuildCollection(response FetchResponse, localState LocalState) (Collection, error) {
	if response.StartedAt.IsZero() || response.CompletedAt.IsZero() || response.CompletedAt.Before(response.StartedAt) {
		return Collection{}, FeedValidationError{Path: "response.timestamps", Message: "fetch timestamps must be present and ordered"}
	}
	if err := validateHTTPSURL("response.SourceURL", response.SourceURL); err != nil {
		return Collection{}, err
	}
	feed, err := decodeAndValidateFeed(response.Body)
	if err != nil {
		return Collection{}, err
	}
	if feed.LastCheck.After(response.CompletedAt) {
		return Collection{}, FeedValidationError{Path: "LastCheck", Message: fmt.Sprintf("timestamp %s is later than fetch completion %s", feed.LastCheck.Format(time.RFC3339Nano), response.CompletedAt.Format(time.RFC3339Nano))}
	}
	feedArtifact, artifactReference := buildFeedArtifact(response.Body)
	evidenceID := "evidence.sofa.macos-v2-feed"
	hostAssessment := assessHostRelease(feed, localState, response.CompletedAt, evidenceID)
	xProtectAssessment := assessXProtect(feed, localState, response.CompletedAt, evidenceID)
	findings := make([]model.Finding, 0, 2)
	if hostAssessment.Finding != nil {
		findings = append(findings, *hostAssessment.Finding)
	}
	if xProtectAssessment.Finding != nil {
		findings = append(findings, *xProtectAssessment.Finding)
	}
	return Collection{
		Tools: []model.ToolRecord{
			{
				ID:      "sofa",
				Name:    "SOFA macOS data feed",
				Version: feed.Version,
				Kind:    model.ToolKindFeed,
				Origin:  response.SourceURL,
				Data: &model.DataIdentity{
					Version:   feed.SchemaVersion,
					UpdatedAt: feed.LastCheck,
					SHA256:    artifactReference.SHA256,
				},
			},
		},
		Coverage: []model.CoverageRecord{
			{
				ID:                "coverage.sofa.macos-security",
				CollectorID:       "sofa",
				Area:              model.CoverageAreaAppleUpdates,
				Target:            "installed macOS release security posture",
				Status:            hostAssessment.CoverageStatus,
				Reason:            hostAssessment.CoverageReason,
				PrivilegeRequired: false,
				StartedAt:         response.StartedAt,
				CompletedAt:       response.CompletedAt,
			},
			{
				ID:                "coverage.sofa.xprotect",
				CollectorID:       "sofa",
				Area:              model.CoverageAreaAppleUpdates,
				Target:            "installed XProtect versions",
				Status:            xProtectAssessment.CoverageStatus,
				Reason:            xProtectAssessment.CoverageReason,
				PrivilegeRequired: false,
				StartedAt:         response.StartedAt,
				CompletedAt:       response.CompletedAt,
			},
		},
		Evidence: []model.EvidenceRecord{
			{
				ID:          evidenceID,
				CollectorID: "sofa",
				Kind:        model.EvidenceKindAPIResponse,
				ObservedAt:  response.CompletedAt,
				Subject:     "SOFA v2 macOS security and XProtect feed",
				Summary:     fmt.Sprintf("SOFA feed version %s schema %s last checked %s", feed.Version, feed.SchemaVersion, feed.LastCheck.Format(time.RFC3339Nano)),
				Command:     nil,
				Artifact:    &artifactReference,
			},
		},
		Findings:  findings,
		Artifacts: []artifact.Record{feedArtifact},
	}, nil
}

func BuildFailure(response FetchResponse, collectionError error) Collection {
	evidenceID := "evidence.sofa.failure"
	evidenceKind := model.EvidenceKindObservation
	var artifactReference *model.ArtifactReference
	artifacts := make([]artifact.Record, 0, 1)
	if len(response.Body) > 0 {
		record, reference := buildFeedArtifact(response.Body)
		artifactReference = &reference
		artifacts = append(artifacts, record)
		evidenceKind = model.EvidenceKindAPIResponse
	}
	return Collection{
		Tools: make([]model.ToolRecord, 0),
		Coverage: []model.CoverageRecord{
			{
				ID:                "coverage.sofa.failure",
				CollectorID:       "macscope",
				Area:              model.CoverageAreaAppleUpdates,
				Target:            "SOFA macOS security and XProtect feed analysis",
				Status:            model.CoverageStatusFailed,
				Reason:            collectionError.Error(),
				PrivilegeRequired: false,
				StartedAt:         response.StartedAt,
				CompletedAt:       response.CompletedAt,
			},
		},
		Evidence: []model.EvidenceRecord{
			{
				ID:          evidenceID,
				CollectorID: "macscope",
				Kind:        evidenceKind,
				ObservedAt:  response.CompletedAt,
				Subject:     "SOFA v2 feed collection",
				Summary:     collectionError.Error(),
				Command:     nil,
				Artifact:    artifactReference,
			},
		},
		Findings:  []model.Finding{buildSOFAFailureFinding(collectionError, response.CompletedAt, evidenceID)},
		Artifacts: artifacts,
	}
}

func decodeAndValidateFeed(body []byte) (Feed, error) {
	var feed Feed
	if err := json.Unmarshal(body, &feed); err != nil {
		return Feed{}, FeedValidationError{Path: "$", Message: fmt.Sprintf("decode JSON: %v", err)}
	}
	if err := validateFeed(feed); err != nil {
		return Feed{}, err
	}
	return feed, nil
}

func validateFeed(feed Feed) error {
	if feed.Version != "2.0" {
		return FeedValidationError{Path: "Version", Message: fmt.Sprintf("value %q is unsupported; expected %q", feed.Version, "2.0")}
	}
	if strings.TrimSpace(feed.SchemaVersion) == "" {
		return FeedValidationError{Path: "SchemaVersion", Message: "value is required"}
	}
	if feed.LastCheck.IsZero() {
		return FeedValidationError{Path: "LastCheck", Message: "valid timestamp is required"}
	}
	if !sha256Pattern.MatchString(feed.UpdateHash) {
		return FeedValidationError{Path: "UpdateHash", Message: fmt.Sprintf("value %q is not a lowercase SHA-256 digest", feed.UpdateHash)}
	}
	if len(feed.OSVersions) == 0 {
		return FeedValidationError{Path: "OSVersions", Message: "at least one OS version is required"}
	}
	for index, osVersion := range feed.OSVersions {
		pathPrefix := fmt.Sprintf("OSVersions[%d]", index)
		if strings.TrimSpace(osVersion.OSVersion) == "" {
			return FeedValidationError{Path: pathPrefix + ".OSVersion", Message: "value is required"}
		}
		if len(osVersion.SecurityReleases) == 0 {
			return FeedValidationError{Path: pathPrefix + ".SecurityReleases", Message: "at least one security release is required"}
		}
		if err := validateSecurityRelease(osVersion.Latest, pathPrefix+".Latest"); err != nil {
			return err
		}
		if osVersion.Latest.ProductVersion != osVersion.SecurityReleases[0].ProductVersion {
			return FeedValidationError{Path: pathPrefix + ".Latest.ProductVersion", Message: "must match the first security release"}
		}
		previousProductVersion := ""
		for releaseIndex, release := range osVersion.SecurityReleases {
			releasePath := fmt.Sprintf("%s.SecurityReleases[%d]", pathPrefix, releaseIndex)
			if err := validateSecurityRelease(release, releasePath); err != nil {
				return err
			}
			if previousProductVersion != "" {
				comparison, comparisonErr := compareProductVersions(previousProductVersion, release.ProductVersion)
				if comparisonErr != nil {
					return FeedValidationError{Path: releasePath + ".ProductVersion", Message: comparisonErr.Error()}
				}
				if comparison < 0 {
					return FeedValidationError{Path: releasePath + ".ProductVersion", Message: "security releases must be ordered from highest to lowest product version"}
				}
			}
			previousProductVersion = release.ProductVersion
		}
	}
	if err := validatePositiveInteger("XProtectPayloads.com.apple.XProtectFramework.XProtect", feed.XProtectPayloads.FrameworkVersion); err != nil {
		return err
	}
	if err := validatePositiveInteger("XProtectPayloads.com.apple.XprotectFramework.PluginService", feed.XProtectPayloads.PluginVersion); err != nil {
		return err
	}
	if feed.XProtectPayloads.ReleaseDate.IsZero() {
		return FeedValidationError{Path: "XProtectPayloads.ReleaseDate", Message: "valid timestamp is required"}
	}
	if err := validatePositiveInteger("XProtectPlistConfigData.com.apple.XProtect", feed.XProtectPlistConfigData.Version); err != nil {
		return err
	}
	if feed.XProtectPlistConfigData.ReleaseDate.IsZero() {
		return FeedValidationError{Path: "XProtectPlistConfigData.ReleaseDate", Message: "valid timestamp is required"}
	}
	return nil
}

func validateSecurityRelease(release SecurityRelease, pathPrefix string) error {
	if strings.TrimSpace(release.ProductVersion) == "" {
		return FeedValidationError{Path: pathPrefix + ".ProductVersion", Message: "value is required"}
	}
	if _, err := parseProductVersion(release.ProductVersion); err != nil {
		return FeedValidationError{Path: pathPrefix + ".ProductVersion", Message: err.Error()}
	}
	if release.ReleaseDate.IsZero() {
		return FeedValidationError{Path: pathPrefix + ".ReleaseDate", Message: "valid timestamp is required"}
	}
	if release.AllBuilds == nil {
		return FeedValidationError{Path: pathPrefix + ".AllBuilds", Message: "array must not be null"}
	}
	if release.CVEs == nil {
		return FeedValidationError{Path: pathPrefix + ".CVEs", Message: "object must not be null"}
	}
	if release.ActivelyExploitedCVEs == nil {
		return FeedValidationError{Path: pathPrefix + ".ActivelyExploitedCVEs", Message: "array must not be null"}
	}
	for identifier, metadata := range release.CVEs {
		if !cvePattern.MatchString(identifier) {
			return FeedValidationError{Path: pathPrefix + ".CVEs", Message: fmt.Sprintf("key %q is not a valid CVE identifier", identifier)}
		}
		if metadata.NISTURL != "" {
			if err := validateHTTPSURL(pathPrefix+".CVEs."+identifier+".NISTURL", metadata.NISTURL); err != nil {
				return err
			}
		}
	}
	for index, identifier := range release.ActivelyExploitedCVEs {
		if !cvePattern.MatchString(identifier) {
			return FeedValidationError{Path: fmt.Sprintf("%s.ActivelyExploitedCVEs[%d]", pathPrefix, index), Message: fmt.Sprintf("value %q is not a valid CVE identifier", identifier)}
		}
	}
	if release.SecurityInfo != "" {
		if err := validateHTTPSURL(pathPrefix+".SecurityInfo", release.SecurityInfo); err != nil {
			return err
		}
	}
	return nil
}

func compareProductVersions(first string, second string) (int, error) {
	firstParts, err := parseProductVersion(first)
	if err != nil {
		return 0, err
	}
	secondParts, err := parseProductVersion(second)
	if err != nil {
		return 0, err
	}
	partCount := max(len(firstParts), len(secondParts))
	for index := 0; index < partCount; index++ {
		firstPart := uint64(0)
		secondPart := uint64(0)
		if index < len(firstParts) {
			firstPart = firstParts[index]
		}
		if index < len(secondParts) {
			secondPart = secondParts[index]
		}
		if firstPart > secondPart {
			return 1, nil
		}
		if firstPart < secondPart {
			return -1, nil
		}
	}
	return 0, nil
}

func parseProductVersion(value string) ([]uint64, error) {
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("value %q must contain two or three numeric components", value)
	}
	parsed := make([]uint64, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("value %q contains an empty component", value)
		}
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("value %q contains non-numeric component %q", value, part)
		}
		parsed = append(parsed, number)
	}
	return parsed, nil
}

func validatePositiveInteger(path string, value string) error {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 {
		return FeedValidationError{Path: path, Message: fmt.Sprintf("value %q must be a positive integer", value)}
	}
	return nil
}

func validateHTTPSURL(path string, value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return FeedValidationError{Path: path, Message: fmt.Sprintf("value %q must be an absolute HTTPS URL", value)}
	}
	return nil
}

func buildFeedArtifact(body []byte) (artifact.Record, model.ArtifactReference) {
	path := "evidence/sofa/macos_data_feed_v2.json"
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	return artifact.Record{Path: path, Content: append([]byte(nil), body...)}, model.ArtifactReference{
		Path:      path,
		SHA256:    digest,
		MediaType: "application/json",
	}
}

func assessHostRelease(feed Feed, localState LocalState, observedAt time.Time, evidenceID string) hostReleaseAssessment {
	matchingOS, found := findOSVersion(feed.OSVersions, localState.MacOSVersion)
	if !found {
		reason := fmt.Sprintf("installed macOS version %q does not match any SOFA OSVersions entry", localState.MacOSVersion)
		finding := buildCoverageGapFinding("macos-release-match", "SOFA could not place the installed macOS version in its release history", reason, observedAt, evidenceID)
		return hostReleaseAssessment{CoverageStatus: model.CoverageStatusPartial, CoverageReason: reason, Finding: &finding}
	}
	releaseIndex, found := findInstalledRelease(matchingOS.SecurityReleases, localState.MacOSVersion, localState.MacOSBuild)
	if !found {
		reason := fmt.Sprintf("installed macOS %s build %s does not exactly match a SOFA security release", localState.MacOSVersion, localState.MacOSBuild)
		finding := buildCoverageGapFinding("macos-release-match", "SOFA could not exactly match the installed macOS release", reason, observedAt, evidenceID)
		return hostReleaseAssessment{CoverageStatus: model.CoverageStatusPartial, CoverageReason: reason, Finding: &finding}
	}
	if releaseIndex == 0 {
		return hostReleaseAssessment{CoverageStatus: model.CoverageStatusComplete, CoverageReason: "", Finding: nil}
	}
	newerReleases := matchingOS.SecurityReleases[:releaseIndex]
	vulnerabilities := vulnerabilityReferences(newerReleases)
	if len(vulnerabilities) == 0 {
		finding := buildUpdateFinding(localState, matchingOS.Latest, len(newerReleases), observedAt, evidenceID)
		return hostReleaseAssessment{CoverageStatus: model.CoverageStatusComplete, CoverageReason: "", Finding: &finding}
	}
	finding := buildOSVulnerabilityFinding(localState, matchingOS.Latest, newerReleases, vulnerabilities, observedAt, evidenceID)
	return hostReleaseAssessment{CoverageStatus: model.CoverageStatusComplete, CoverageReason: "", Finding: &finding}
}

func findOSVersion(osVersions []OSVersion, installedVersion string) (OSVersion, bool) {
	installedMajor := versionMajor(installedVersion)
	for _, osVersion := range osVersions {
		if versionMajor(osVersion.Latest.ProductVersion) == installedMajor {
			return osVersion, true
		}
	}
	return OSVersion{}, false
}

func findInstalledRelease(releases []SecurityRelease, installedVersion string, installedBuild string) (int, bool) {
	for index, release := range releases {
		if release.ProductVersion != installedVersion {
			continue
		}
		knownBuilds := append([]string(nil), release.AllBuilds...)
		if release.Build != "" && !slices.Contains(knownBuilds, release.Build) {
			knownBuilds = append(knownBuilds, release.Build)
		}
		if len(knownBuilds) == 0 || slices.Contains(knownBuilds, installedBuild) {
			return index, true
		}
	}
	return 0, false
}

func versionMajor(version string) string {
	major, _, _ := strings.Cut(version, ".")
	return major
}

func vulnerabilityReferences(releases []SecurityRelease) []model.VulnerabilityReference {
	metadataByID := make(map[string]CVEMetadata)
	activelyExploited := make(map[string]struct{})
	for _, release := range releases {
		for identifier, metadata := range release.CVEs {
			current := metadataByID[identifier]
			metadataByID[identifier] = mergeCVEMetadata(current, metadata)
		}
		for _, identifier := range release.ActivelyExploitedCVEs {
			activelyExploited[identifier] = struct{}{}
			if _, exists := metadataByID[identifier]; !exists {
				metadataByID[identifier] = CVEMetadata{}
			}
		}
	}
	identifiers := make([]string, 0, len(metadataByID))
	for identifier := range metadataByID {
		identifiers = append(identifiers, identifier)
	}
	slices.Sort(identifiers)
	result := make([]model.VulnerabilityReference, 0, len(identifiers))
	for _, identifier := range identifiers {
		metadata := metadataByID[identifier]
		_, listedAsExploited := activelyExploited[identifier]
		vulnerabilityURL := metadata.NISTURL
		if vulnerabilityURL == "" {
			vulnerabilityURL = "https://nvd.nist.gov/vuln/detail/" + identifier
		}
		result = append(result, model.VulnerabilityReference{
			ID:             identifier,
			Namespace:      model.VulnerabilityNamespaceCVE,
			CVSS:           nil,
			EPSS:           nil,
			KnownExploited: metadata.InKEV || metadata.ActivelyExploited || listedAsExploited,
			URL:            vulnerabilityURL,
		})
	}
	return result
}

func mergeCVEMetadata(current CVEMetadata, additional CVEMetadata) CVEMetadata {
	return CVEMetadata{
		NISTURL:           firstNonempty(additional.NISTURL, current.NISTURL),
		ActivelyExploited: current.ActivelyExploited || additional.ActivelyExploited,
		InKEV:             current.InKEV || additional.InKEV,
		Severity:          higherSeverity(current.Severity, additional.Severity),
	}
}

func firstNonempty(preferred string, alternative string) string {
	if preferred != "" {
		return preferred
	}
	return alternative
}

func higherSeverity(first string, second string) string {
	if severityRank(second) > severityRank(first) {
		return second
	}
	return first
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func buildOSVulnerabilityFinding(localState LocalState, latest SecurityRelease, newerReleases []SecurityRelease, vulnerabilities []model.VulnerabilityReference, observedAt time.Time, evidenceID string) model.Finding {
	knownExploitedCount := 0
	for _, vulnerability := range vulnerabilities {
		if vulnerability.KnownExploited {
			knownExploitedCount++
		}
	}
	severity := releaseFindingSeverity(newerReleases, knownExploitedCount)
	references := releaseReferences(newerReleases)
	return model.Finding{
		ID:              "finding.sofa.macos-update",
		Category:        model.FindingCategoryOSVulnerability,
		Title:           fmt.Sprintf("macOS %s is behind SOFA release %s", localState.MacOSVersion, latest.ProductVersion),
		Description:     fmt.Sprintf("SOFA lists %d newer release(s) that address %d unique CVE(s), including %d marked actively exploited or in KEV. This is a version-based exposure inference, not proof that an exploit ran or that every CVE applies to this hardware configuration.", len(newerReleases), len(vulnerabilities), knownExploitedCount),
		Severity:        severity,
		Confidence:      model.ConfidenceHigh,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources: []model.SourceReference{
			{ToolID: "sofa", RuleID: "sofa.macos.release-posture", RuleVersion: "2"},
		},
		EvidenceIDs: []string{evidenceID, "evidence.native.macos-version"},
		AffectedComponents: []model.AffectedComponent{
			{Kind: model.AffectedComponentOS, Identifier: "macos", Name: "macOS", Version: localState.MacOSVersion},
		},
		Vulnerabilities: vulnerabilities,
		Remediation: model.Remediation{
			Summary:         fmt.Sprintf("Update macOS to %s build %s or a later Apple-supported release after normal compatibility review and backup.", latest.ProductVersion, latest.Build),
			Steps:           []string{"Open System Settings, select General, select Software Update, and install the latest compatible macOS update."},
			RequiresAdmin:   true,
			RequiresRestart: true,
			References:      references,
		},
	}
}

func buildUpdateFinding(localState LocalState, latest SecurityRelease, newerReleaseCount int, observedAt time.Time, evidenceID string) model.Finding {
	return model.Finding{
		ID:              "finding.sofa.macos-update",
		Category:        model.FindingCategoryConfiguration,
		Title:           fmt.Sprintf("macOS %s is behind SOFA release %s", localState.MacOSVersion, latest.ProductVersion),
		Description:     fmt.Sprintf("SOFA lists %d newer release(s), but those feed entries contain no CVE identifiers. This is an update-posture finding, not a vulnerability claim.", newerReleaseCount),
		Severity:        model.SeverityLow,
		Confidence:      model.ConfidenceHigh,
		Status:          model.FindingStatusDetected,
		FirstObservedAt: observedAt,
		Sources:         []model.SourceReference{{ToolID: "sofa", RuleID: "sofa.macos.release-posture", RuleVersion: "2"}},
		EvidenceIDs:     []string{evidenceID, "evidence.native.macos-version"},
		AffectedComponents: []model.AffectedComponent{
			{Kind: model.AffectedComponentOS, Identifier: "macos", Name: "macOS", Version: localState.MacOSVersion},
		},
		Vulnerabilities: make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         fmt.Sprintf("Update macOS to %s build %s or a later Apple-supported release after normal compatibility review and backup.", latest.ProductVersion, latest.Build),
			Steps:           []string{"Open System Settings, select General, select Software Update, and install the latest compatible macOS update."},
			RequiresAdmin:   true,
			RequiresRestart: true,
			References:      releaseReferences([]SecurityRelease{latest}),
		},
	}
}

func releaseFindingSeverity(releases []SecurityRelease, knownExploitedCount int) model.Severity {
	if knownExploitedCount > 0 {
		return model.SeverityCritical
	}
	highestRank := 0
	for _, release := range releases {
		highestRank = max(highestRank, severityRank(release.UpdateSummary.Priority))
		for _, metadata := range release.CVEs {
			highestRank = max(highestRank, severityRank(metadata.Severity))
		}
	}
	switch highestRank {
	case 4:
		return model.SeverityCritical
	case 3:
		return model.SeverityHigh
	case 2:
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

func releaseReferences(releases []SecurityRelease) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(releases)+1)
	result = append(result, FeedURL)
	seen[FeedURL] = struct{}{}
	for _, release := range releases {
		if release.SecurityInfo == "" {
			continue
		}
		if _, exists := seen[release.SecurityInfo]; exists {
			continue
		}
		seen[release.SecurityInfo] = struct{}{}
		result = append(result, release.SecurityInfo)
	}
	return result
}

func assessXProtect(feed Feed, localState LocalState, observedAt time.Time, feedEvidenceID string) xProtectAssessment {
	components := []outdatedXProtectComponent{
		{Identifier: "com.apple.XProtect", Name: "XProtect configuration data", InstalledVersion: localState.XProtectConfigVersion, CurrentVersion: feed.XProtectPlistConfigData.Version, EvidenceID: "evidence.native.xprotect-config-version"},
		{Identifier: "com.apple.XProtectFramework.XProtect", Name: "XProtect framework", InstalledVersion: localState.XProtectVersion, CurrentVersion: feed.XProtectPayloads.FrameworkVersion, EvidenceID: "evidence.native.xprotect-framework-version"},
		{Identifier: "com.apple.XprotectFramework.PluginService", Name: "XProtect plugin service", InstalledVersion: localState.XProtectPluginVersion, CurrentVersion: feed.XProtectPayloads.PluginVersion, EvidenceID: "evidence.native.xprotect-plugin-version"},
	}
	missing := make([]string, 0)
	outdated := make([]outdatedXProtectComponent, 0)
	for _, component := range components {
		if component.InstalledVersion == "" {
			missing = append(missing, component.Name)
			continue
		}
		installed, installedErr := strconv.ParseUint(component.InstalledVersion, 10, 64)
		current, currentErr := strconv.ParseUint(component.CurrentVersion, 10, 64)
		if installedErr != nil || currentErr != nil {
			missing = append(missing, component.Name+" version comparison")
			continue
		}
		if installed < current {
			outdated = append(outdated, component)
		}
	}
	var finding *model.Finding
	if len(outdated) > 0 {
		builtFinding := buildXProtectFinding(outdated, observedAt, feedEvidenceID)
		finding = &builtFinding
	}
	if len(missing) > 0 {
		return xProtectAssessment{
			CoverageStatus: model.CoverageStatusPartial,
			CoverageReason: "could not compare " + strings.Join(missing, ", "),
			Finding:        finding,
		}
	}
	return xProtectAssessment{CoverageStatus: model.CoverageStatusComplete, CoverageReason: "", Finding: finding}
}

func buildXProtectFinding(outdated []outdatedXProtectComponent, observedAt time.Time, feedEvidenceID string) model.Finding {
	components := make([]model.AffectedComponent, 0, len(outdated))
	evidenceIDs := []string{feedEvidenceID}
	descriptions := make([]string, 0, len(outdated))
	for _, component := range outdated {
		components = append(components, model.AffectedComponent{
			Kind:       model.AffectedComponentPackage,
			Identifier: component.Identifier,
			Name:       component.Name,
			Version:    component.InstalledVersion,
		})
		evidenceIDs = append(evidenceIDs, component.EvidenceID)
		descriptions = append(descriptions, fmt.Sprintf("%s installed=%s SOFA=%s", component.Name, component.InstalledVersion, component.CurrentVersion))
	}
	return model.Finding{
		ID:                 "finding.sofa.xprotect-update",
		Category:           model.FindingCategoryConfiguration,
		Title:              "Installed XProtect data is behind the SOFA baseline",
		Description:        strings.Join(descriptions, "; ") + ". This is an update-posture finding, not evidence that malware is present.",
		Severity:           model.SeverityHigh,
		Confidence:         model.ConfidenceHigh,
		Status:             model.FindingStatusDetected,
		FirstObservedAt:    observedAt,
		Sources:            []model.SourceReference{{ToolID: "sofa", RuleID: "sofa.xprotect.version-posture", RuleVersion: "2"}},
		EvidenceIDs:        evidenceIDs,
		AffectedComponents: components,
		Vulnerabilities:    make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         "Install current Apple security-response and system-data updates.",
			Steps:           []string{"Open System Settings, select General, select Software Update, open Automatic Updates, and enable Install Security Responses and system files; then allow macOS to retrieve the current data."},
			RequiresAdmin:   true,
			RequiresRestart: false,
			References:      []string{FeedURL, "https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web"},
		},
	}
}

func buildCoverageGapFinding(ruleID string, title string, description string, observedAt time.Time, evidenceID string) model.Finding {
	return model.Finding{
		ID:                 "finding.sofa." + ruleID + ".coverage-gap",
		Category:           model.FindingCategoryCoverageGap,
		Title:              title,
		Description:        description + ". No macOS vulnerability exposure conclusion was produced.",
		Severity:           model.SeverityInfo,
		Confidence:         model.ConfidenceConfirmed,
		Status:             model.FindingStatusDetected,
		FirstObservedAt:    observedAt,
		Sources:            []model.SourceReference{{ToolID: "sofa", RuleID: "sofa." + ruleID + ".coverage", RuleVersion: "2"}},
		EvidenceIDs:        []string{evidenceID, "evidence.native.macos-version"},
		AffectedComponents: []model.AffectedComponent{{Kind: model.AffectedComponentScanner, Identifier: "macscope.sofa.macos-release-match", Name: "SOFA macOS release matcher"}},
		Vulnerabilities:    make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         "Review the preserved SOFA feed and installed macOS version evidence, then run a new scan after SOFA includes the release.",
			Steps:           []string{"Compare the installed ProductVersion and BuildVersion with the preserved SOFA SecurityReleases entries."},
			RequiresAdmin:   false,
			RequiresRestart: false,
			References:      []string{FeedURL},
		},
	}
}

func buildSOFAFailureFinding(collectionError error, observedAt time.Time, evidenceID string) model.Finding {
	return model.Finding{
		ID:                 "finding.sofa.tool-error",
		Category:           model.FindingCategoryToolError,
		Title:              "SOFA feed analysis failed",
		Description:        collectionError.Error() + ". MacScope did not claim that macOS or XProtect is current.",
		Severity:           model.SeverityLow,
		Confidence:         model.ConfidenceConfirmed,
		Status:             model.FindingStatusDetected,
		FirstObservedAt:    observedAt,
		Sources:            []model.SourceReference{{ToolID: "macscope", RuleID: "sofa.feed.execution", RuleVersion: "1"}},
		EvidenceIDs:        []string{evidenceID},
		AffectedComponents: []model.AffectedComponent{{Kind: model.AffectedComponentScanner, Identifier: "macscope.sofa", Name: "SOFA feed adapter"}},
		Vulnerabilities:    make([]model.VulnerabilityReference, 0),
		Remediation: model.Remediation{
			Summary:         "Resolve the reported network, HTTP, or schema error and run a new scan.",
			Steps:           []string{"Confirm the SOFA v2 feed is reachable over HTTPS and inspect any preserved response artifact before retrying."},
			RequiresAdmin:   false,
			RequiresRestart: false,
			References:      []string{FeedURL},
		},
	}
}
