#!/bin/bash
set -euo pipefail

# Prepare the existing pinned build components without executing any scanner.
if [[ "$#" -ne 2 ]]; then
  printf 'Usage: prepare-macos-runtime.sh <repository-root> <new-download-directory>\n' >&2
  exit 64
fi
readonly repository_root="$1"
readonly download_directory="$2"
readonly lock_file="$repository_root/tools.lock.json"

if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  printf 'MacScope runtime bundling requires a macOS arm64 build host.\n' >&2
  exit 65
fi
if [[ -e "$repository_root/.tools" || -L "$repository_root/.tools" ]]; then
  printf 'Build component directory already exists: %s\n' "$repository_root/.tools" >&2
  exit 66
fi
jq -e '.schema_version == "1" and .tools.go.platform == "darwin-arm64"' "$lock_file" >/dev/null
go_version="$(jq -er '.tools.go.version | select(type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' "$lock_file")"
go_binary="$(command -v go)"
readonly go_version go_binary
if [[ "$(go version)" != "go version go$go_version darwin/arm64" ]]; then
  printf 'Build requires the Go version and platform pinned in tools.lock.json: go%s darwin/arm64.\n' "$go_version" >&2
  exit 67
fi
mkdir "$download_directory"
mkdir -p "$repository_root/.tools/go/bin"
ln -s "$go_binary" "$repository_root/.tools/go/bin/go"

download_archive() {
  local tool="$1"
  local publisher="$2"
  local release_prefix="$3"
  local version archive url digest
  jq -e --arg tool "$tool" '.tools[$tool].platform == "darwin-arm64"' "$lock_file" >/dev/null
  version="$(jq -er --arg tool "$tool" '.tools[$tool].version | select(type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' "$lock_file")"
  archive="$(jq -er --arg tool "$tool" '.tools[$tool].archive | select(type == "string" and test("^[A-Za-z0-9._-]+\\.tar\\.gz$"))' "$lock_file")"
  url="$(jq -er --arg tool "$tool" '.tools[$tool].url | select(type == "string")' "$lock_file")"
  digest="$(jq -er --arg tool "$tool" '.tools[$tool].archive_sha256 | select(type == "string" and test("^[a-f0-9]{64}$"))' "$lock_file")"
  if [[ "$url" != "https://github.com/$publisher/releases/download/$release_prefix$version/$archive" ]]; then
    printf 'Pinned %s archive has an unexpected source URL.\n' "$tool" >&2
    return 68
  fi
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 \
    "$url" --output "$download_directory/$tool.tar.gz"
  printf '%s  %s\n' "$digest" "$download_directory/$tool.tar.gz" | shasum -a 256 --check
  mkdir -p "$repository_root/.tools/$tool/$version"
}

download_archive osquery osquery/osquery ''
download_archive syft anchore/syft v
download_archive grype anchore/grype v

osquery_version="$(jq -er '.tools.osquery.version' "$lock_file")"
syft_version="$(jq -er '.tools.syft.version' "$lock_file")"
grype_version="$(jq -er '.tools.grype.version' "$lock_file")"
readonly osquery_version syft_version grype_version
COPYFILE_DISABLE=1 tar -xzf "$download_directory/osquery.tar.gz" \
  -C "$repository_root/.tools/osquery/$osquery_version" --strip-components=3 opt/osquery/lib/osquery.app
ln -s osquery.app/Contents/MacOS/osqueryd "$repository_root/.tools/osquery/$osquery_version/osqueryi"
tar -xzf "$download_directory/syft.tar.gz" -C "$repository_root/.tools/syft/$syft_version" syft
tar -xzf "$download_directory/grype.tar.gz" -C "$repository_root/.tools/grype/$grype_version" grype

for tool in osquery syft grype; do
  version="$(jq -er --arg tool "$tool" '.tools[$tool].version' "$lock_file")"
  digest="$(jq -er --arg tool "$tool" '.tools[$tool].executable_sha256 | select(type == "string" and test("^[a-f0-9]{64}$"))' "$lock_file")"
  executable="$repository_root/.tools/$tool/$version/$tool"
  if [[ "$tool" == osquery ]]; then
    executable="$repository_root/.tools/osquery/$version/osqueryi"
  fi
  printf '%s  %s\n' "$digest" "$executable" | shasum -a 256 --check
done
codesign --verify --deep --strict "$repository_root/.tools/osquery/$osquery_version/osquery.app"
