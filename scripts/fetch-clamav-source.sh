#!/usr/bin/env bash
#
# Download the ClamAV source corresponding to an engine version ClamMac can
# install.
#
# ClamMac does not redistribute ClamAV, so it carries no obligation to convey
# ClamAV's source. This script exists anyway: anyone auditing what ClamMac
# downloads and runs should be able to get the matching source without going
# hunting for it.
#
#   ./scripts/fetch-clamav-source.sh              # every pinned version
#   ./scripts/fetch-clamav-source.sh 1.5.4        # one version
#   ./scripts/fetch-clamav-source.sh --list       # what is pinned

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/clammac/resources/engine_manifest.json"
OUTPUT_DIR="${CLAMMAC_SOURCE_DIR:-$REPO_ROOT/clamav-source}"

if [[ ! -f "$MANIFEST" ]]; then
  echo "error: cannot find $MANIFEST" >&2
  exit 1
fi

versions() {
  python3 -c "
import json, sys
data = json.load(open('$MANIFEST'))
for release in data.get('releases', []):
    print(release['version'], release.get('source_url', ''), sep='\t')
"
}

if [[ "${1:-}" == "--list" ]]; then
  echo "ClamAV versions pinned by ClamMac:"
  versions | while IFS=$'\t' read -r version url; do
    printf '  %-10s %s\n' "$version" "${url:-<no source url recorded>}"
  done
  exit 0
fi

wanted="${1:-}"
found=0
mkdir -p "$OUTPUT_DIR"

while IFS=$'\t' read -r version url; do
  [[ -n "$wanted" && "$version" != "$wanted" ]] && continue
  found=1

  if [[ -z "$url" ]]; then
    echo "skipping $version: no source URL recorded in the manifest" >&2
    continue
  fi

  target="$OUTPUT_DIR/clamav-$version.tar.gz"
  echo "==> ClamAV $version"
  echo "    $url"
  if [[ -f "$target" ]]; then
    echo "    already downloaded: $target"
  else
    curl --fail --location --progress-bar --output "$target.part" "$url"
    mv "$target.part" "$target"
    echo "    saved to $target"
  fi
  echo "    sha256: $(shasum -a 256 "$target" 2>/dev/null | cut -d' ' -f1 || sha256sum "$target" | cut -d' ' -f1)"
done < <(versions)

if [[ -n "$wanted" && "$found" -eq 0 ]]; then
  echo "error: version '$wanted' is not pinned in the manifest." >&2
  echo "Run with --list to see what is." >&2
  exit 1
fi

echo
echo "ClamAV is distributed by its authors under the GNU General Public License,"
echo "version 2. Its licence and copyright notices are inside each tarball."
