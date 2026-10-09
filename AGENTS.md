# MacScope repository instructions

- Preserve the read-only scanner contract, fixed privilege boundary, evidence schema, tool digests, and explicit coverage limits.
- Keep changes uncommitted until the user authorizes a commit; commit, push, PR creation, merge, release, deployment, and privileged testing each require authorization covering that operation.
- Preserve the `macOS build and test` Go gate and the `Swift app build` gate for every PR. `.github/workflows/ci.yml` owns their commands; `.github/scripts/prepare-macos-runtime.sh` prepares only digest-verified build components from `tools.lock.json`.
- Preserve successful Go and Actions CodeQL categories while tracing the explicit native Swift build. Confirm each language's successful analysis at the reviewed revision; a Go scan does not validate the Swift application.
- Hosted CI must not run a host scan, invoke privileged collectors, update vulnerability databases, hydrate cloud files, or upload private reports. Downloaded tools are bundled and verified without being launched.
- Keep private host reports, databases, downloaded tools, and scan results outside Git and published CI artifacts. Native runtime and privileged-helper validation remain separate release gates.
