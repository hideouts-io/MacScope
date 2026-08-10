package report

const reportTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>MacScope report — {{.Run.Host.Hostname}}</title>
<style>
:root { color-scheme: light dark; --bg:#0b1020; --panel:#151c30; --text:#edf2f7; --muted:#9eabc3; --line:#2c3752; --critical:#ff5c6c; --high:#ff9966; --medium:#ffd166; --low:#66b3ff; --info:#9eabc3; --ok:#59d499; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
main { width:min(1180px,calc(100% - 32px)); margin:32px auto 64px; }
h1,h2,h3 { line-height:1.2; }
h1 { margin:0 0 8px; font-size:32px; }
h2 { margin-top:36px; }
a { color:#8bc4ff; overflow-wrap:anywhere; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; overflow-wrap:anywhere; }
.muted { color:var(--muted); }
.notice { border:1px solid var(--line); border-left:4px solid var(--medium); background:var(--panel); padding:14px 16px; border-radius:8px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:22px 0; }
.metric { padding:16px; border:1px solid var(--line); border-radius:10px; background:var(--panel); }
.metric strong { display:block; font-size:26px; }
.critical { color:var(--critical); } .high { color:var(--high); } .medium { color:var(--medium); } .low { color:var(--low); } .info { color:var(--info); } .complete { color:var(--ok); }
table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); }
th,td { padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.05em; }
.badge { display:inline-block; border:1px solid currentColor; border-radius:999px; padding:2px 8px; margin:0 5px 4px 0; font-size:12px; font-weight:600; }
details { margin:10px 0; border:1px solid var(--line); border-radius:10px; background:var(--panel); }
summary { cursor:pointer; padding:14px 16px; font-weight:650; }
.detail { padding:0 16px 18px; }
.detail-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:16px; }
.detail h4 { margin:18px 0 6px; }
.detail ul,.detail ol { margin-top:6px; padding-left:22px; }
.meta { display:grid; grid-template-columns:max-content 1fr; gap:5px 14px; }
.meta dt { color:var(--muted); } .meta dd { margin:0; overflow-wrap:anywhere; }
footer { margin-top:42px; color:var(--muted); border-top:1px solid var(--line); padding-top:16px; }
@media print { :root { color-scheme:light; --bg:#fff; --panel:#fff; --text:#111; --muted:#555; --line:#ccc; } main { width:100%; margin:0; } details { break-inside:avoid; } details > * { display:block; } }
</style>
</head>
<body>
<main>
<header>
<h1>MacScope security report</h1>
<p class="muted">Validated scan <code>{{.Run.RunID}}</code> for {{.Run.Host.Hostname}}</p>
</header>

<section class="notice">
<strong>Interpretation boundary:</strong> Findings describe observed configuration or package-version matches. They do not by themselves prove exploitation, malicious activity, or host compromise. Review coverage gaps before drawing conclusions.
</section>

<section class="grid" aria-label="Finding counts">
<div class="metric"><span>Total findings</span><strong>{{.SeverityCounts.Total}}</strong></div>
<div class="metric critical"><span>Critical</span><strong>{{.SeverityCounts.Critical}}</strong></div>
<div class="metric high"><span>High</span><strong>{{.SeverityCounts.High}}</strong></div>
<div class="metric medium"><span>Medium</span><strong>{{.SeverityCounts.Medium}}</strong></div>
<div class="metric low"><span>Low</span><strong>{{.SeverityCounts.Low}}</strong></div>
<div class="metric info"><span>Informational</span><strong>{{.SeverityCounts.Info}}</strong></div>
</section>

<h2>Scan identity</h2>
<dl class="meta">
<dt>Status</dt><dd><span class="badge {{.Run.Status}}">{{.Run.Status}}</span></dd>
<dt>Host</dt><dd>{{.Run.Host.Hostname}}</dd>
<dt>macOS</dt><dd>{{.Run.Host.MacOSVersion}} {{.Run.Host.MacOSBuild}} · {{.Run.Host.Architecture}}</dd>
<dt>Hardware</dt><dd>{{.Run.Host.ModelID}} · {{.Run.Host.Chip}}</dd>
<dt>Started</dt><dd>{{.StartedAt}}</dd>
<dt>Completed</dt><dd>{{.CompletedAt}} · {{.Duration}}</dd>
<dt>Privilege</dt><dd>requested={{.Run.Privilege.Requested}}, granted={{.Run.Privilege.Granted}}, collector={{.Run.Privilege.Collector}}</dd>
<dt>Source</dt><dd><code>{{.SourceName}}</code></dd>
<dt>Source SHA-256</dt><dd><code>{{.SourceSHA256}}</code></dd>
</dl>

<h2>Coverage</h2>
<div class="grid" aria-label="Coverage counts">
<div class="metric complete"><span>Complete</span><strong>{{.CoverageCounts.Complete}}</strong></div>
<div class="metric medium"><span>Partial</span><strong>{{.CoverageCounts.Partial}}</strong></div>
<div class="metric info"><span>Not scanned</span><strong>{{.CoverageCounts.NotScanned}}</strong></div>
<div class="metric critical"><span>Failed</span><strong>{{.CoverageCounts.Failed}}</strong></div>
</div>
<table>
<thead><tr><th>Status</th><th>Area</th><th>Target and limitation</th><th>Collector</th></tr></thead>
<tbody>
{{range .Coverage}}<tr><td><span class="badge {{.Status}}">{{.Status}}</span></td><td>{{.Area}}</td><td>{{.Target}}{{if .Reason}}<br><span class="muted">{{.Reason}}</span>{{end}}</td><td><code>{{.CollectorID}}</code></td></tr>{{else}}<tr><td colspan="4">No coverage records.</td></tr>{{end}}
</tbody>
</table>

<h2>Prioritized findings</h2>
<p class="muted">Ordered by severity, known-exploited status, confidence, CVSS, EPSS, and stable identity. All validated findings are included.</p>
{{range .Findings}}
<details>
<summary><span class="badge {{.Finding.Severity}}">{{.Finding.Severity}}</span><span class="badge">{{.Finding.Confidence}}</span>{{if .KnownExploited}}<span class="badge critical">known exploited</span>{{end}} {{.Finding.Title}}</summary>
<div class="detail">
<dl class="meta">
<dt>ID</dt><dd><code>{{.Finding.ID}}</code></dd>
<dt>Category</dt><dd>{{.Finding.Category}}</dd>
<dt>Status</dt><dd>{{.Finding.Status}}</dd>
{{if .MaximumCVSS}}<dt>Maximum CVSS</dt><dd>{{.MaximumCVSS}}</dd>{{end}}
{{if .MaximumEPSS}}<dt>Maximum EPSS</dt><dd>{{.MaximumEPSS}}</dd>{{end}}
</dl>
<p>{{.Finding.Description}}</p>
<div class="detail-grid">
<section><h4>Affected components</h4><ul>{{range .Finding.AffectedComponents}}<li><strong>{{.Name}}</strong>{{if .Version}} {{.Version}}{{end}}{{if .Path}}<br><code>{{.Path}}</code>{{end}}</li>{{end}}</ul></section>
{{if .Finding.Vulnerabilities}}<section><h4>Vulnerabilities</h4><ul>{{range .Finding.Vulnerabilities}}<li><a href="{{.URL}}" rel="noreferrer">{{.ID}}</a>{{if .KnownExploited}} — known exploited{{end}}{{if .CVSS}} · CVSS {{cvss .CVSS}}{{end}}{{if .EPSS}} · EPSS {{epss .EPSS}}{{end}}</li>{{end}}</ul></section>{{end}}
</div>
<h4>Remediation</h4><p>{{.Finding.Remediation.Summary}}</p><ol>{{range .Finding.Remediation.Steps}}<li>{{.}}</li>{{end}}</ol>
{{if .Finding.Remediation.References}}<h4>References</h4><ul>{{range .Finding.Remediation.References}}<li><a href="{{.}}" rel="noreferrer">{{.}}</a></li>{{end}}</ul>{{end}}
<p class="muted">Evidence: <code>{{join .Finding.EvidenceIDs ", "}}</code></p>
</div>
</details>
{{else}}<p>No findings were recorded.</p>{{end}}

<footer>Generated offline by MacScope {{.Run.Scanner.Version}} from validated schema {{.Run.SchemaVersion}} JSON. Raw evidence contents are not embedded.</footer>
</main>
</body>
</html>
`
