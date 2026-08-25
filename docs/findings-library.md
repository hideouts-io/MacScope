# MacScope Findings Library

This handbook describes every rule family MacScope can emit. It is generated from the same validated catalog used by the application and scanner; it is not a report of findings detected on a particular Mac.

Catalog schema: `1`

## Rule families

- [Native macOS security control](#native-macos-security-control) — `macscope`
- [Apple release and XProtect posture](#apple-release-and-xprotect-posture) — `sofa`
- [mSCP configuration control](#mscp-configuration-control) — `mscp`
- [osquery inventory and exposure query](#osquery-inventory-and-exposure-query) — `osquery`
- [Package vulnerability match](#package-vulnerability-match) — `grype`
- [MacScope orchestration and coverage](#macscope-orchestration-and-coverage) — `macscope`

## Native macOS security control

| Field | Value |
|---|---|
| Catalog ID | `native-security-controls` |
| Instrument | `macscope` |
| Rule matching | `prefix` · `native.` |
| Category | `configuration` |

### Explanation

- A fixed read-only macOS command is parsed into an expected or failed security-control observation.

### Detection logic

- Typed parsers validate command output; execution and coverage failures remain separate evidence-backed findings.

### Expected state

- The control reports the secure state defined by the individual native rule.

### Observed-state interpretation

- A failed state means the named protection is weaker than expected; an execution or permission failure means the state is unknown.

### Severity rationale

- The individual control assigns severity according to the protection weakened by the observed state.

### Expected evidence

- Executable and arguments
- Exit status and exact output
- Parsed observation and artifact hash

### Possible false positives

- An intentionally disabled control may be required by a documented operational workflow

### Limitations

- A weakened control does not prove exploitation or compromise

### Remediation

- Follow the finding-specific ordered steps after reviewing operational impact

### Verification

- Run a new scan and confirm the rule passes with comparable coverage

### Supported macOS versions

- macOS 26 Tahoe

### References

- <https://support.apple.com/guide/security/welcome/web>

## Apple release and XProtect posture

| Field | Value |
|---|---|
| Catalog ID | `sofa-release-and-xprotect` |
| Instrument | `sofa` |
| Rule matching | `prefix` · `sofa.` |
| Category | `os_vulnerability` |

### Explanation

- The installed macOS build and XProtect versions are compared with validated SOFA security-feed records.

### Detection logic

- Installed versions are matched to current feed records; unavailable or inconsistent data becomes a coverage finding.

### Expected state

- The installed macOS build and XProtect data meet the latest applicable validated SOFA records.

### Observed-state interpretation

- An older version indicates update exposure; unavailable feed or version evidence indicates unknown coverage rather than a pass.

### Severity rationale

- Security-release and known-exploited context determine priority; missing feed coverage is never a pass.

### Expected evidence

- Installed build
- Installed XProtect versions
- Validated SOFA response and feed identity

### Possible false positives

- A staged enterprise update rollout may intentionally lag the latest public release
- SOFA may not yet describe a newly released macOS build

### Limitations

- Release metadata does not prove exploitation
- Network or feed failure limits conclusions

### Remediation

- Install applicable macOS and security-data updates from System Settings

### Verification

- Rescan and confirm installed versions match current feed records

### Supported macOS versions

- macOS 26 Tahoe

### References

- <https://support.apple.com/en-us/100100>
- <https://sofa.macadmins.io/>

## mSCP configuration control

| Field | Value |
|---|---|
| Catalog ID | `mscp-configuration` |
| Instrument | `mscp` |
| Rule matching | `vulnerability` · `mscp-rule-identifier` |
| Category | `configuration` |

### Explanation

- A reviewed subset of the NIST macOS Security Compliance Project baseline is evaluated with validated evidence.

### Detection logic

- Observed values are compared with the expected CIS Level 1 value for the supported macOS release.

### Expected state

- The observed value matches the pinned CIS Level 1 expectation for the supported macOS release.

### Observed-state interpretation

- A mismatch is a configuration finding; unsupported platforms or uncollected evidence are coverage gaps.

### Severity rationale

- Severity reflects control impact and is not a claim of compromise.

### Expected evidence

- Stable mSCP rule ID
- Observed and expected values
- Baseline and coverage identity

### Possible false positives

- An approved compensating control or documented business exception may justify a different setting

### Limitations

- MacScope implements a documented subset
- Unsupported systems are coverage gaps

### Remediation

- Follow the finding-specific guidance after reviewing operational impact

### Verification

- Rescan with the same baseline and comparable coverage

### Supported macOS versions

- macOS 26 Tahoe

### References

- <https://github.com/usnistgov/macos_security>

## osquery inventory and exposure query

| Field | Value |
|---|---|
| Catalog ID | `osquery-inventory` |
| Instrument | `osquery` |
| Rule matching | `prefix` · `query.` |
| Category | `tool_error` |

### Explanation

- Pinned osquery queries inventory applications, persistence mechanisms, and listening sockets.

### Detection logic

- Structured query results are validated before becoming evidence; execution or parse failure becomes a tool error.

### Expected state

- The query completes with valid structured output and every returned record can be reviewed in operational context.

### Observed-state interpretation

- An inventory record establishes presence only; a failed query removes coverage and does not imply that no records exist.

### Severity rationale

- Inventory presence is contextual; failure priority reflects the coverage it removes.

### Expected evidence

- Pinned executable hash
- SQL argument and JSON output
- Target coverage

### Possible false positives

- Legitimate software commonly installs launch items or opens local listening sockets

### Limitations

- Persistence or a listener does not establish malicious intent or reachability

### Remediation

- Verify owning software and business purpose before changing it

### Verification

- Rescan the same target and compare validated records

### Supported macOS versions

- macOS 26 Tahoe

### References

- <https://osquery.io/>

## Package vulnerability match

| Field | Value |
|---|---|
| Catalog ID | `grype-vulnerability-match` |
| Instrument | `grype` |
| Rule matching | `vulnerability` · `vulnerability-identifier` |
| Category | `software_vulnerability` |

### Explanation

- A package and version in the validated Syft SBOM matched a record in the validated Grype database.

### Detection logic

- The SBOM, database identity, match report, identifiers, and post-scan database digest are validated.

### Expected state

- Installed package versions have no applicable matches in the validated vulnerability database.

### Observed-state interpretation

- A match identifies a package/version requiring applicability review; it does not establish reachability, execution, or exploitation.

### Severity rationale

- Severity, CVSS, EPSS, and known-exploited status guide priority while reachability remains contextual.

### Expected evidence

- Package identity
- Grype match
- Database version, source, time, and hash

### Possible false positives

- Vendor backports may fix a vulnerability without changing the upstream version string
- The matched component may be installed but unreachable in the deployed configuration

### Limitations

- A package match does not prove vulnerable code is reachable or executed
- Vendor confirmation may be required

### Remediation

- Update or remove the package through its authoritative distribution channel

### Verification

- Regenerate the SBOM and rerun matching with comparable coverage

### Supported macOS versions

- macOS 26 Tahoe

### References

- <https://github.com/anchore/grype>
- <https://github.com/anchore/syft>

## MacScope orchestration and coverage

| Field | Value |
|---|---|
| Catalog ID | `macscope-orchestration` |
| Instrument | `macscope` |
| Rule matching | `vulnerability` · `macscope-rule-identifier` |
| Category | `coverage_gap` |

### Explanation

- Tool provenance, execution, validation, network, and scope failures are reported instead of being treated as clean.

### Detection logic

- A failed required operation creates linked evidence, coverage, and an explanatory finding.

### Expected state

- Required tools, permissions, data sources, and targets complete with validated evidence.

### Observed-state interpretation

- A failure or exclusion limits the conclusion for the named target and must remain unknown until comparable coverage succeeds.

### Severity rationale

- Priority reflects missing evidence, not inferred compromise.

### Expected evidence

- Operation and error
- Affected instrument or path
- Coverage state

### Possible false positives

- An intentionally offline scan or approved exclusion can produce an expected coverage gap

### Limitations

- A coverage gap means unknown, not vulnerable and not secure

### Remediation

- Resolve the reported permission, integrity, network, database, or execution issue

### Verification

- Confirm the affected coverage record becomes complete in a later scan

### Supported macOS versions

- macOS 26 Tahoe

### References

- <https://github.com/hideouts-io/MacScope>
