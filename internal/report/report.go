package report

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"macscope/internal/model"
)

const maximumScanDocumentBytes int64 = 512 * 1024 * 1024

type Result struct {
	OutputPath string
}

type InputError struct {
	Path  string
	Cause error
}

func (err InputError) Error() string {
	return fmt.Sprintf("read report input %q: %v", err.Path, err.Cause)
}

func (err InputError) Unwrap() error {
	return err.Cause
}

type OutputError struct {
	Path  string
	Cause error
}

func (err OutputError) Error() string {
	return fmt.Sprintf("write HTML report %q: %v", err.Path, err.Cause)
}

func (err OutputError) Unwrap() error {
	return err.Cause
}

type severityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
}

type coverageCounts struct {
	Complete   int
	Partial    int
	NotScanned int
	Failed     int
	Total      int
}

type findingView struct {
	Finding        model.Finding
	KnownExploited bool
	MaximumCVSS    string
	MaximumEPSS    string
}

type reportView struct {
	Run            model.ScanRun
	SourceName     string
	SourceSHA256   string
	StartedAt      string
	CompletedAt    string
	Duration       string
	SeverityCounts severityCounts
	CoverageCounts coverageCounts
	Coverage       []model.CoverageRecord
	Findings       []findingView
}

func Generate(inputPath string, outputPath string) (Result, error) {
	absoluteInput, err := filepath.Abs(inputPath)
	if err != nil {
		return Result{}, InputError{Path: inputPath, Cause: fmt.Errorf("resolve absolute input path: %w", err)}
	}
	run, digest, err := readScanRun(absoluteInput)
	if err != nil {
		return Result{}, err
	}
	view := buildReportView(run, filepath.Base(absoluteInput), digest)
	content, err := renderReport(view)
	if err != nil {
		return Result{}, fmt.Errorf("render validated scan report: %w", err)
	}
	absoluteOutput, err := filepath.Abs(outputPath)
	if err != nil {
		return Result{}, OutputError{Path: outputPath, Cause: fmt.Errorf("resolve absolute output path: %w", err)}
	}
	if err := writeReport(absoluteOutput, content); err != nil {
		return Result{}, err
	}
	return Result{OutputPath: absoluteOutput}, nil
}

func readScanRun(path string) (model.ScanRun, string, error) {
	information, err := os.Stat(path)
	if err != nil {
		return model.ScanRun{}, "", InputError{Path: path, Cause: fmt.Errorf("stat scan document: %w", err)}
	}
	if !information.Mode().IsRegular() {
		return model.ScanRun{}, "", InputError{Path: path, Cause: fmt.Errorf("scan document is not a regular file")}
	}
	if information.Size() > maximumScanDocumentBytes {
		return model.ScanRun{}, "", InputError{Path: path, Cause: fmt.Errorf("scan document size %d exceeds limit %d", information.Size(), maximumScanDocumentBytes)}
	}
	file, err := os.Open(path)
	if err != nil {
		return model.ScanRun{}, "", InputError{Path: path, Cause: fmt.Errorf("open scan document: %w", err)}
	}
	hasher := sha256.New()
	run, decodeErr := model.DecodeScanRun(io.TeeReader(file, hasher))
	closeErr := file.Close()
	if decodeErr != nil {
		if closeErr != nil {
			decodeErr = errors.Join(decodeErr, fmt.Errorf("close invalid scan document: %w", closeErr))
		}
		return model.ScanRun{}, "", InputError{Path: path, Cause: decodeErr}
	}
	if closeErr != nil {
		return model.ScanRun{}, "", InputError{Path: path, Cause: fmt.Errorf("close scan document: %w", closeErr)}
	}
	return run, fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

func buildReportView(run model.ScanRun, sourceName string, sourceSHA256 string) reportView {
	return reportView{
		Run:            run,
		SourceName:     sourceName,
		SourceSHA256:   sourceSHA256,
		StartedAt:      run.StartedAt.Format(time.RFC3339),
		CompletedAt:    run.CompletedAt.Format(time.RFC3339),
		Duration:       run.CompletedAt.Sub(run.StartedAt).Round(time.Millisecond).String(),
		SeverityCounts: countSeverities(run.Findings),
		CoverageCounts: countCoverage(run.Coverage),
		Coverage:       prioritizeCoverage(run.Coverage),
		Findings:       buildFindingViews(prioritizeFindings(run.Findings)),
	}
}

func countSeverities(findings []model.Finding) severityCounts {
	counts := severityCounts{Total: len(findings)}
	for _, finding := range findings {
		switch finding.Severity {
		case model.SeverityCritical:
			counts.Critical++
		case model.SeverityHigh:
			counts.High++
		case model.SeverityMedium:
			counts.Medium++
		case model.SeverityLow:
			counts.Low++
		case model.SeverityInfo:
			counts.Info++
		}
	}
	return counts
}

func countCoverage(records []model.CoverageRecord) coverageCounts {
	counts := coverageCounts{Total: len(records)}
	for _, record := range records {
		switch record.Status {
		case model.CoverageStatusComplete:
			counts.Complete++
		case model.CoverageStatusPartial:
			counts.Partial++
		case model.CoverageStatusNotScanned:
			counts.NotScanned++
		case model.CoverageStatusFailed:
			counts.Failed++
		}
	}
	return counts
}

func prioritizeCoverage(records []model.CoverageRecord) []model.CoverageRecord {
	prioritized := append([]model.CoverageRecord(nil), records...)
	sort.SliceStable(prioritized, func(first int, second int) bool {
		firstPriority := coveragePriority(prioritized[first].Status)
		secondPriority := coveragePriority(prioritized[second].Status)
		if firstPriority != secondPriority {
			return firstPriority > secondPriority
		}
		if prioritized[first].Area != prioritized[second].Area {
			return prioritized[first].Area < prioritized[second].Area
		}
		return prioritized[first].ID < prioritized[second].ID
	})
	return prioritized
}

func prioritizeFindings(findings []model.Finding) []model.Finding {
	prioritized := append([]model.Finding(nil), findings...)
	sort.SliceStable(prioritized, func(first int, second int) bool {
		firstFinding := prioritized[first]
		secondFinding := prioritized[second]
		if severityPriority(firstFinding.Severity) != severityPriority(secondFinding.Severity) {
			return severityPriority(firstFinding.Severity) > severityPriority(secondFinding.Severity)
		}
		if findingKnownExploited(firstFinding) != findingKnownExploited(secondFinding) {
			return findingKnownExploited(firstFinding)
		}
		if confidencePriority(firstFinding.Confidence) != confidencePriority(secondFinding.Confidence) {
			return confidencePriority(firstFinding.Confidence) > confidencePriority(secondFinding.Confidence)
		}
		if findingMaximumCVSS(firstFinding) != findingMaximumCVSS(secondFinding) {
			return findingMaximumCVSS(firstFinding) > findingMaximumCVSS(secondFinding)
		}
		if findingMaximumEPSS(firstFinding) != findingMaximumEPSS(secondFinding) {
			return findingMaximumEPSS(firstFinding) > findingMaximumEPSS(secondFinding)
		}
		if firstFinding.Title != secondFinding.Title {
			return firstFinding.Title < secondFinding.Title
		}
		return firstFinding.ID < secondFinding.ID
	})
	return prioritized
}

func buildFindingViews(findings []model.Finding) []findingView {
	views := make([]findingView, 0, len(findings))
	for _, finding := range findings {
		maximumCVSS := findingMaximumCVSS(finding)
		maximumEPSS := findingMaximumEPSS(finding)
		cvssText := ""
		epssText := ""
		if maximumCVSS >= 0 {
			cvssText = fmt.Sprintf("%.1f", maximumCVSS)
		}
		if maximumEPSS >= 0 {
			epssText = fmt.Sprintf("%.2f%%", maximumEPSS*100)
		}
		views = append(views, findingView{
			Finding:        finding,
			KnownExploited: findingKnownExploited(finding),
			MaximumCVSS:    cvssText,
			MaximumEPSS:    epssText,
		})
	}
	return views
}

func findingKnownExploited(finding model.Finding) bool {
	for _, vulnerability := range finding.Vulnerabilities {
		if vulnerability.KnownExploited {
			return true
		}
	}
	return false
}

func findingMaximumCVSS(finding model.Finding) float64 {
	maximum := -1.0
	for _, vulnerability := range finding.Vulnerabilities {
		if vulnerability.CVSS != nil && *vulnerability.CVSS > maximum {
			maximum = *vulnerability.CVSS
		}
	}
	return maximum
}

func findingMaximumEPSS(finding model.Finding) float64 {
	maximum := -1.0
	for _, vulnerability := range finding.Vulnerabilities {
		if vulnerability.EPSS != nil && *vulnerability.EPSS > maximum {
			maximum = *vulnerability.EPSS
		}
	}
	return maximum
}

func severityPriority(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func confidencePriority(confidence model.Confidence) int {
	switch confidence {
	case model.ConfidenceConfirmed:
		return 4
	case model.ConfidenceHigh:
		return 3
	case model.ConfidenceMedium:
		return 2
	case model.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func coveragePriority(status model.CoverageStatus) int {
	switch status {
	case model.CoverageStatusFailed:
		return 4
	case model.CoverageStatusNotScanned:
		return 3
	case model.CoverageStatusPartial:
		return 2
	case model.CoverageStatusComplete:
		return 1
	default:
		return 0
	}
}

func renderReport(view reportView) ([]byte, error) {
	parsed, err := template.New("macscope-report").Funcs(template.FuncMap{
		"cvss": formatCVSS,
		"epss": formatEPSS,
		"join": strings.Join,
	}).Parse(reportTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse embedded HTML template: %w", err)
	}
	var buffer bytes.Buffer
	if err := parsed.Execute(&buffer, view); err != nil {
		return nil, fmt.Errorf("execute embedded HTML template: %w", err)
	}
	return buffer.Bytes(), nil
}

func formatCVSS(value *float64) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%.1f", *value)
}

func formatEPSS(value *float64) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%.2f%%", *value*100)
}

func writeReport(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return OutputError{Path: path, Cause: fmt.Errorf("create output directory: %w", err)}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if errors.Is(err, os.ErrExist) {
		return OutputError{Path: path, Cause: fmt.Errorf("report already exists; choose a new output path")}
	}
	if err != nil {
		return OutputError{Path: path, Cause: fmt.Errorf("create report without overwriting existing data: %w", err)}
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return OutputError{Path: path, Cause: fmt.Errorf("write report: %w", err)}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return OutputError{Path: path, Cause: fmt.Errorf("sync report: %w", err)}
	}
	if err := file.Close(); err != nil {
		return OutputError{Path: path, Cause: fmt.Errorf("close report: %w", err)}
	}
	return nil
}
