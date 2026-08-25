package catalogdoc

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"macscope/internal/catalog"
)

func RenderMarkdown(document catalog.Document) ([]byte, error) {
	if strings.TrimSpace(document.SchemaVersion) == "" || len(document.Rules) == 0 {
		return nil, fmt.Errorf("render findings handbook as Markdown: catalog must be validated and non-empty")
	}

	var output strings.Builder
	output.WriteString("# MacScope Findings Library\n\n")
	output.WriteString("This handbook describes every rule family MacScope can emit. It is generated from the same validated catalog used by the application and scanner; it is not a report of findings detected on a particular Mac.\n\n")
	output.WriteString("Catalog schema: `" + escapeMarkdown(document.SchemaVersion) + "`\n\n")
	output.WriteString("## Rule families\n\n")
	for _, entry := range document.Rules {
		output.WriteString("- [" + escapeMarkdown(entry.Title) + "](#" + markdownAnchor(entry.Title) + ") — `" + escapeMarkdown(entry.ToolID) + "`\n")
	}
	for _, entry := range document.Rules {
		writeMarkdownEntry(&output, entry)
	}
	return []byte(output.String()), nil
}

func RenderHTML(document catalog.Document) ([]byte, error) {
	if strings.TrimSpace(document.SchemaVersion) == "" || len(document.Rules) == 0 {
		return nil, fmt.Errorf("render findings handbook as HTML: catalog must be validated and non-empty")
	}
	templateValue, err := template.New("findings-handbook").Funcs(template.FuncMap{
		"anchor": markdownAnchor,
	}).Parse(htmlDocumentTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse findings handbook HTML template: %w", err)
	}
	var output bytes.Buffer
	if err := templateValue.Execute(&output, document); err != nil {
		return nil, fmt.Errorf("render findings handbook as HTML: %w", err)
	}
	return output.Bytes(), nil
}

func writeMarkdownEntry(output *strings.Builder, entry catalog.Entry) {
	output.WriteString("\n## " + escapeMarkdown(entry.Title) + "\n\n")
	output.WriteString("| Field | Value |\n|---|---|\n")
	output.WriteString("| Catalog ID | `" + escapeMarkdown(entry.ID) + "` |\n")
	output.WriteString("| Instrument | `" + escapeMarkdown(entry.ToolID) + "` |\n")
	output.WriteString("| Rule matching | `" + escapeMarkdown(string(entry.RuleMatch)) + "` · `" + escapeMarkdown(entry.RuleValue) + "` |\n")
	output.WriteString("| Category | `" + escapeMarkdown(string(entry.Category)) + "` |\n")
	writeMarkdownSection(output, "Explanation", []string{entry.Explanation})
	writeMarkdownSection(output, "Detection logic", []string{entry.DetectionLogic})
	writeMarkdownSection(output, "Expected state", []string{entry.ExpectedState})
	writeMarkdownSection(output, "Observed-state interpretation", []string{entry.ObservedState})
	writeMarkdownSection(output, "Severity rationale", []string{entry.SeverityRationale})
	writeMarkdownSection(output, "Expected evidence", entry.ExpectedEvidence)
	writeMarkdownSection(output, "Possible false positives", entry.FalsePositives)
	writeMarkdownSection(output, "Limitations", entry.Limitations)
	writeMarkdownSection(output, "Remediation", entry.Remediation)
	writeMarkdownSection(output, "Verification", entry.Verification)
	writeMarkdownSection(output, "Supported macOS versions", entry.SupportedMacOS)
	output.WriteString("\n### References\n\n")
	for _, reference := range entry.References {
		output.WriteString("- <" + reference + ">\n")
	}
}

func writeMarkdownSection(output *strings.Builder, title string, values []string) {
	output.WriteString("\n### " + title + "\n\n")
	for _, value := range values {
		output.WriteString("- " + escapeMarkdown(value) + "\n")
	}
}

func escapeMarkdown(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "|", "\\|", "`", "\\`")
	return replacer.Replace(value)
}

func markdownAnchor(value string) string {
	var output strings.Builder
	previousDash := false
	for _, character := range strings.ToLower(value) {
		isLetter := character >= 'a' && character <= 'z'
		isNumber := character >= '0' && character <= '9'
		if isLetter || isNumber {
			output.WriteRune(character)
			previousDash = false
			continue
		}
		if output.Len() > 0 && !previousDash {
			output.WriteByte('-')
			previousDash = true
		}
	}
	return strings.Trim(output.String(), "-")
}

const htmlDocumentTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MacScope Findings Library</title>
<style>
:root { color-scheme: light dark; --accent: #c61d35; --panel: color-mix(in srgb, Canvas 94%, CanvasText 6%); --border: color-mix(in srgb, CanvasText 18%, transparent); }
* { box-sizing: border-box; }
body { margin: 0; font: 16px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: Canvas; color: CanvasText; }
header { padding: 3.5rem clamp(1.25rem, 5vw, 5rem); color: white; background: linear-gradient(135deg, #701020, #c61d35 60%, #e14c60); }
header p { max-width: 58rem; margin-bottom: 0; opacity: .92; }
main { width: min(74rem, calc(100% - 2.5rem)); margin: 2rem auto 5rem; }
nav, article { border: 1px solid var(--border); border-radius: 16px; background: var(--panel); box-shadow: 0 12px 30px rgba(0,0,0,.08); }
nav { padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }
nav ul { columns: 2; padding-left: 1.25rem; }
article { padding: clamp(1.25rem, 3vw, 2.25rem); margin: 1.25rem 0; }
h1, h2, h3 { line-height: 1.2; }
h2 { margin-top: 0; }
a { color: var(--accent); }
.metadata { display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); gap: .75rem; }
.metadata div { padding: .75rem; border: 1px solid var(--border); border-radius: 10px; }
.label { display: block; font-size: .78rem; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; opacity: .66; }
code { overflow-wrap: anywhere; }
@media (max-width: 650px) { nav ul { columns: 1; } header { padding-top: 2.5rem; } }
@media print { header { background: none; color: black; padding: 1rem 0; } nav, article { box-shadow: none; break-inside: avoid; } }
</style>
</head>
<body>
<header><h1>MacScope Findings Library</h1><p>This handbook describes every rule family MacScope can emit. It is generated from the same validated catalog used by the application and scanner; it is not a report of findings detected on a particular Mac.</p></header>
<main>
<nav aria-label="Rule families"><h2>Rule families</h2><ul>{{range .Rules}}<li><a href="#{{anchor .Title}}">{{.Title}}</a> · <code>{{.ToolID}}</code></li>{{end}}</ul></nav>
{{range .Rules}}<article id="{{anchor .Title}}">
<h2>{{.Title}}</h2>
<div class="metadata"><div><span class="label">Catalog ID</span><code>{{.ID}}</code></div><div><span class="label">Instrument</span><code>{{.ToolID}}</code></div><div><span class="label">Rule matching</span><code>{{.RuleMatch}} · {{.RuleValue}}</code></div><div><span class="label">Category</span><code>{{.Category}}</code></div></div>
<h3>Explanation</h3><p>{{.Explanation}}</p>
<h3>Detection logic</h3><p>{{.DetectionLogic}}</p>
<h3>Expected state</h3><p>{{.ExpectedState}}</p>
<h3>Observed-state interpretation</h3><p>{{.ObservedState}}</p>
<h3>Severity rationale</h3><p>{{.SeverityRationale}}</p>
<h3>Expected evidence</h3><ul>{{range .ExpectedEvidence}}<li>{{.}}</li>{{end}}</ul>
<h3>Possible false positives</h3><ul>{{range .FalsePositives}}<li>{{.}}</li>{{end}}</ul>
<h3>Limitations</h3><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>
<h3>Remediation</h3><ol>{{range .Remediation}}<li>{{.}}</li>{{end}}</ol>
<h3>Verification</h3><ol>{{range .Verification}}<li>{{.}}</li>{{end}}</ol>
<h3>Supported macOS versions</h3><ul>{{range .SupportedMacOS}}<li>{{.}}</li>{{end}}</ul>
<h3>References</h3><ul>{{range .References}}<li><a href="{{.}}" rel="noreferrer">{{.}}</a></li>{{end}}</ul>
</article>{{end}}
</main>
</body>
</html>
`
