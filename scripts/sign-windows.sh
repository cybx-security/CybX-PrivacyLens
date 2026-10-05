#!/usr/bin/env bash
# Signs the Windows .exe files in dist/ from macOS/Linux using osslsigncode
# (brew install osslsigncode).
#
# You need a code-signing certificate. Options, roughly by price:
#   - Azure Trusted Signing (~$10/mo, recommended): cloud signing service,
#     works with SmartScreen reputation. Uses its own CLI instead of this
#     script — see README.
#   - OV certificate (Sectigo, SSL.com, Certum ~$70-250/yr): since June 2023
#     these ship on hardware tokens or cloud HSMs, so signing usually happens
#     via the vendor's tool (e.g. SSL.com eSigner) or on a Windows machine
#     with signtool.exe. This script covers the legacy .pfx-file case.
#   - EV certificate (~$250-400/yr): instant SmartScreen reputation.
#
# Usage (PFX file):
#   PFX_FILE=cert.pfx PFX_PASS=secret ./scripts/sign-windows.sh
set -euo pipefail
cd "$(dirname "$0")/.."

: "${PFX_FILE:?set PFX_FILE to your .pfx certificate path}"
: "${PFX_PASS:?set PFX_PASS to the certificate password}"
TIMESTAMP_URL="${TIMESTAMP_URL:-http://timestamp.digicert.com}"
PUBLISHER_URL="${PUBLISHER_URL:-}" # optional: company website embedded in the signature

command -v osslsigncode >/dev/null || { echo "brew install osslsigncode"; exit 1; }

for exe in dist/privacylens-windows-*.exe dist/privacylens-gui-windows-*.exe; do
  [ -e "$exe" ] || { echo "no windows binaries in dist/ — run scripts/build-all.sh first"; exit 1; }
  case "$exe" in *-signed.exe) continue;; esac
  echo "signing $exe"
  osslsigncode sign \
    -pkcs12 "$PFX_FILE" -pass "$PFX_PASS" \
    -n "PrivacyLens" ${PUBLISHER_URL:+-i "$PUBLISHER_URL"} \
    -t "$TIMESTAMP_URL" \
    -in "$exe" -out "${exe%.exe}-signed.exe"
  osslsigncode verify "${exe%.exe}-signed.exe" || true
  mv "${exe%.exe}-signed.exe" "$exe"
done

echo "done"
