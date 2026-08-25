# MacScope GUI Roadmap

This roadmap turns the existing evidence-first Go scanner into a polished native macOS application while preserving the command-line interface, immutable scan evidence, explicit coverage gaps, and narrow privilege boundary.

## 1. GUI event protocol and cancellable scan engine — complete

- [x] Define a versioned NDJSON envelope with ordered sequence numbers and UTC timestamps.
- [x] Define typed scan-started, progress, scan-completed, and scan-failed payloads.
- [x] Add `macscope scan --events-json` with stdout reserved exclusively for NDJSON events.
- [x] Suppress the animated banner and terminal progress in machine-event mode.
- [x] Add stable collector IDs to progress events.
- [x] Pass one caller-owned context through native, SOFA, osquery, Syft, Grype, and privileged collection.
- [x] Cancel active subprocesses on `SIGINT` or `SIGTERM` and emit a final cancellation failure event.
- [x] Define typed command-started, command-output, and command-completed events.
- [x] Stream stdout and stderr chunks without waiting for command completion.
- [x] Mark output that may contain private host data. Redacted export remains part of phase 12.
- [x] Preserve full command output in hashed local evidence artifacts.
- [x] Add protocol envelope, ordering, cancellation, CLI parsing, and normal CLI compatibility tests.
- [x] Document the current lifecycle and progress event schema for the Swift client.
- [x] Add command-event decoding fixtures and exact binary chunk reconstruction tests.

Acceptance criteria:

- A GUI process can start one scan, parse every stdout line as schema-valid JSON, identify the active instrument, cancel safely, and locate the final validated `scan.json` without scraping terminal text.
- Normal CLI users retain the current banner, human-readable progress, warnings, errors, and final report path.

## 2. Native macOS application shell — in progress

- [x] Create an Xcode project using Swift and SwiftUI.
- [x] Use AppKit only for macOS controls that SwiftUI does not provide well.
- [x] Add a sidebar with Dashboard, New Scan, Live Activity, Attention, Findings, Instruments, Coverage, History, Findings Library, and Settings.
- [x] Use the simplified MacScope dashboard icon for the application and Dock icon.
- [x] Use the full MacScope logo on the welcome screen. About, report, and installer artwork remain release work.
- [x] Add accessible labels, keyboard navigation, scalable text, and stable accessibility identifiers to primary flows. A full VoiceOver audit remains a release gate.
- [x] Add light and dark appearances with a consistent severity color system that does not rely on color alone.

Acceptance criteria:

- A user can launch MacScope from Finder and navigate every primary area without Terminal, Xcode, Homebrew, or knowledge of the repository layout.

## 3. Guided scan setup

- [ ] Provide Standard and Enhanced Read-Only scan choices.
- [ ] Explain what privileged coverage adds before requesting authorization.
- [ ] Add file and directory inclusion pickers.
- [ ] Add repeatable file and directory exclusion controls.
- [ ] Skip OneDrive by default and display that decision before scanning.
- [ ] Include locally downloaded iCloud content without forcing cloud-only files to download.
- [ ] Report dataless iCloud items as explicit coverage exclusions.
- [ ] Add optional large-archive exclusions with the resulting coverage impact.
- [ ] Show expected instruments, network access, disk usage, and approximate scan scope.
- [ ] Save named scan profiles without storing credentials.
- [ ] Add a preflight check for free space, required permissions, tool integrity, and database availability.

Acceptance criteria:

- A nontechnical user can understand and approve exactly what will be scanned, excluded, downloaded, and elevated before starting.

## 4. Live Activity

- [ ] Show honest overall orchestration progress and elapsed time.
- [ ] Show queued, running, completed, failed, canceled, and not-scanned states per instrument.
- [ ] Use indeterminate progress when an upstream tool does not expose real item counts.
- [ ] Display the exact executable path and argument array for each nonprivileged command.
- [ ] Display the approved operation name rather than inventing a shell command for privileged helper requests.
- [ ] Stream timestamped stdout and stderr with instrument and command filters.
- [ ] Add search, copy, save, and redacted-export controls.
- [ ] Show artifacts as they are written and findings as they become available.
- [ ] Keep raw output local and warn before exporting host-identifying data.

Acceptance criteria:

- The user can tell which instrument is running, what it requested, what it returned, how long it has run, and whether progress is measured or indeterminate.

## 5. Dashboard and Attention views

- [ ] Show last scan time, run status, host summary, and privilege coverage.
- [ ] Show finding totals by severity without inventing a security score.
- [ ] Highlight known-exploited vulnerabilities.
- [ ] Highlight failed controls, unexpected exposures, persistence findings, threat indicators, tool errors, and coverage gaps.
- [ ] Separate failed tests from not-scanned and unknown results.
- [ ] Explain that an anomaly is an unexpected or failed observation, not proof of compromise.
- [ ] Link every dashboard count to the filtered records behind it.

Acceptance criteria:

- Every summary is traceable to findings or coverage records, and a clean-looking dashboard cannot conceal missing coverage.

## 6. Findings reader and remediation

- [ ] Add search and filters for severity, category, instrument, confidence, KEV status, administrator requirement, and restart requirement.
- [ ] Show what was found, why it was flagged, why it matters, and what it does not prove.
- [ ] Show affected components, CVE/GHSA/OSV references, CVSS, EPSS, and known-exploited status.
- [ ] Link source tools, rule IDs, evidence records, and hashed artifacts.
- [ ] Present remediation as ordered, plain-language steps.
- [ ] Show side effects, administrator requirements, restart requirements, and authoritative references.
- [ ] Add post-remediation verification steps and a targeted rescan action.
- [ ] Keep remediation instructional and read-only for the first release.
- [ ] Require action preview, confirmation, authorization, rollback information, and verification before any future automated remediation.

Acceptance criteria:

- A user can understand, verify, and remediate each result without losing the evidence and interpretation boundaries that produced it.

## 7. Instrument views

- [ ] Add dedicated pages for native MacScope probes, SOFA, mSCP, osquery, Syft, and Grype.
- [ ] Show instrument purpose, version, executable hash, upstream origin, and data provenance.
- [ ] Group findings, evidence, commands, coverage, artifacts, warnings, and errors by instrument.
- [ ] Show scan duration and the exact targets assessed by each instrument.
- [ ] Distinguish unavailable tools from successful tools that found no issues.

Acceptance criteria:

- Every instrument has an independent, readable result page and every finding remains linked to its source instrument and evidence.

## 8. Coverage view

- [ ] Display complete, partial, not-scanned, failed, permission-denied, excluded, cloud-only, tool-unavailable, and network-unavailable states.
- [ ] Show user exclusions and fixed safety exclusions separately.
- [ ] Explain the impact of every gap on conclusions.
- [ ] Add permission guidance for coverage that requires user approval.
- [ ] Prevent “no vulnerabilities found” language when relevant coverage is incomplete.

Acceptance criteria:

- Users can distinguish an observed pass from an unknown result and understand exactly what MacScope did not assess.

## 9. Findings Library and master documentation

- [ ] Create one structured rule catalog as the source of truth for all supported findings.
- [ ] Store stable rule ID, title, category, explanation, detection logic, severity rationale, expected evidence, limitations, remediation, verification, and references.
- [ ] Generate the in-app Findings Library and master Markdown/HTML handbook from the same catalog.
- [ ] Distinguish the complete rule handbook from findings detected in a particular scan.
- [ ] Validate that emitted finding source references resolve to catalog entries.
- [ ] Show which instruments and macOS versions support each rule.

Acceptance criteria:

- GUI explanations, exported documentation, and scanner rules cannot silently drift into conflicting descriptions.

## 10. Scan history and comparisons

- [ ] Preserve each validated scan directory as immutable evidence.
- [ ] Maintain a local index without rewriting historical `scan.json` files.
- [ ] Compare runs as new, persistent, resolved, and coverage-changed.
- [ ] Compare tool versions, database identities, exclusions, and permissions before interpreting differences.
- [ ] Add retention settings and explicit deletion confirmation.
- [ ] Support exporting one run or a comparison report.

Acceptance criteria:

- A resolved label means the later scan had comparable coverage; missing coverage must never be treated as resolution.

## 11. Privileged helper and permissions

- [ ] Keep the SwiftUI app and Go orchestrator unprivileged.
- [ ] Replace GUI `sudo` prompting with a signed, narrowly scoped Service Management helper using XPC.
- [ ] Let macOS Authorization Services own credential and Touch ID prompts.
- [ ] Never accept, read, record, transmit, or store password text.
- [ ] Expose only fixed read-only helper operations; never expose arbitrary root command execution.
- [ ] Validate the signed requesting application before processing XPC requests.
- [ ] Show helper installation, authorization, operation, and result states in the GUI.
- [ ] Add guided Full Disk Access and other permission status checks without changing settings automatically.
- [ ] Threat-model and test the helper protocol before release.

Acceptance criteria:

- Privileged collection expands only documented read-only coverage, and compromise of the GUI cannot turn the helper into a general root shell.

## 12. Local storage, privacy, and exports

- [ ] Store application data under `~/Library/Application Support/MacScope` by default.
- [ ] Keep scans, raw logs, databases, and temporary files out of iCloud Drive and OneDrive unless the user explicitly exports there.
- [ ] Keep telemetry disabled by default.
- [ ] Provide raw local export and separately labeled redacted export.
- [ ] Identify hostnames, usernames, paths, process arguments, and other sensitive fields before export.
- [ ] Preserve artifact SHA-256 values and provenance in portable evidence bundles.
- [ ] Export validated JSON and offline HTML first; add PDF only after layout and evidence-link verification.

Acceptance criteria:

- MacScope performs no silent upload, users control every export destination, and redaction never alters the preserved local original.

## 13. Packaging, updates, and release

- [ ] Bundle the Go engine and supported pinned third-party executables inside `MacScope.app`.
- [ ] Review and include required third-party licenses and acknowledgements.
- [ ] Verify bundled executable versions and hashes before every scan.
- [ ] Download and validate the Grype database with visible first-run progress.
- [ ] Sign nested executables and helpers before signing the outer app.
- [ ] Enable hardened runtime and use a Developer ID identity.
- [ ] Notarize and staple the application and DMG or installer package.
- [ ] Test install, launch, authorization, scanning, cancellation, export, and uninstall on a clean supported Mac.
- [ ] Add a signed update mechanism with release notes and rollback guidance.
- [ ] Publish checksums and a reproducible release manifest on GitHub Releases.

Acceptance criteria:

- A user downloads a signed release, drags MacScope to Applications, launches it normally, and completes a scan without installing developer tools.

## 14. Quality and release gates

- [ ] Keep the Go CLI fully supported and backward compatible.
- [ ] Run Go formatting, vet, race tests, shuffled tests, build, and CLI smoke tests.
- [ ] Add Swift formatting, static analysis, unit tests, and end-to-end application tests.
- [ ] Use accessibility identifiers for UI automation.
- [ ] Test real subprocess and report integrations; avoid mock-only confidence.
- [ ] Test offline, slow-network, canceled, permission-denied, tool-corrupt, database-stale, and low-disk scenarios.
- [ ] Validate all scan and event documents with strict decoders.
- [ ] Verify that no private scans, databases, credentials, or host-specific logs enter Git.
- [ ] Complete an accessibility, privacy, privilege-boundary, and evidence-integrity review before release.

Acceptance criteria:

- The release passes automated checks and a clean-Mac end-to-end test while preserving explicit failure and coverage reporting.
