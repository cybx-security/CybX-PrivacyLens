#!/usr/bin/env bash
# Publishes the packages in dist/ as a GitHub release that installed copies
# of PrivacyLens find through "Check for updates" / "privacylens update".
#
#   ./scripts/build-all.sh            build everything first
#   ./scripts/release.sh [notes.md]   create release v<version> with the
#                                     packages + SHA256SUMS.txt; release
#                                     notes from the file, else generated
#                                     from the commits since the last tag
#
# Needs the GitHub CLI signed in (brew install gh; gh auth login) with
# write access to the repository named by buildinfo.UpdateRepo (override
# with UPDATE_REPO=owner/name). The repository must be PUBLIC: customer
# machines fetch releases anonymously. The updater refuses a release
# without SHA256SUMS.txt, which this script always adds.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "error: $*" >&2; exit 1; }

VERSION=$(sed -n 's/.*Version = "\(.*\)"/\1/p' internal/buildinfo/buildinfo.go)
REPO="${UPDATE_REPO:-$(sed -n 's/.*UpdateRepo = "\(.*\)"/\1/p' internal/buildinfo/buildinfo.go)}"
NOTES="${1:-}"
PKG=dist/packages

command -v gh >/dev/null || die "GitHub CLI not found: brew install gh, then gh auth login"
gh auth status >/dev/null 2>&1 || die "GitHub CLI is not signed in: gh auth login"
ls "$PKG"/*"${VERSION}"* >/dev/null 2>&1 || die "no ${VERSION} packages in ${PKG}; run ./scripts/build-all.sh first"
[ -z "$(git status --porcelain)" ] || die "commit (or stash) your changes first so the release matches a commit"
if gh release view "v${VERSION}" --repo "$REPO" >/dev/null 2>&1; then
  die "release v${VERSION} already exists at github.com/${REPO}; bump Version in internal/buildinfo/buildinfo.go and rebuild"
fi

echo "release v${VERSION} -> github.com/${REPO}"
(cd "$PKG" && rm -f SHA256SUMS.txt && shasum -a 256 ./*"${VERSION}"* | sed 's|  \./|  |' > SHA256SUMS.txt && cat SHA256SUMS.txt)

args=(--repo "$REPO" --title "PrivacyLens ${VERSION}" --target "$(git rev-parse HEAD)")
if [ -n "$NOTES" ]; then
  args+=(--notes-file "$NOTES")
else
  args+=(--generate-notes)
fi
gh release create "v${VERSION}" "$PKG"/*"${VERSION}"* "$PKG/SHA256SUMS.txt" "${args[@]}"
echo
echo "Published. Installed copies will see v${VERSION} on their next \"Check for updates\"."
