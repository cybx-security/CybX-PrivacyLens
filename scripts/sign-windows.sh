#!/usr/bin/env bash
# Signs Windows .exe files (the programs and the setup wizard) from macOS or
# Linux, so Windows shows the publisher's name instead of "Unknown publisher".
# scripts/build-all.sh calls this when SIGN=1.
#
#   ./scripts/sign-windows.sh [file.exe ...]
#
# With no arguments it signs the Windows programs in dist/. Two ways to
# sign, chosen by which variables are set:
#
# 1. Cloud signing service or hardware token, through jsign
#    (brew install jsign). Private keys for publicly trusted code-signing
#    certificates can no longer be exported to a file, so this is what a
#    newly bought certificate needs. Set JSIGN_ARGS to the store options for
#    your provider, for example:
#
#      Azure Trusted Signing:
#        JSIGN_ARGS="--storetype TRUSTEDSIGNING \
#          --keystore <region>.codesigning.azure.net \
#          --storepass $(az account get-access-token --resource https://codesigning.azure.net --query accessToken -o tsv) \
#          --alias <account-name>/<certificate-profile>"
#
#      SSL.com eSigner:
#        JSIGN_ARGS="--storetype ESIGNER --storepass '<user>|<password>' \
#          --alias <credential-id> --keypass <totp-secret>"
#
#    See https://ebourg.github.io/jsign/ for every supported store.
#
# 2. A legacy .pfx certificate file, through osslsigncode
#    (brew install osslsigncode):
#        PFX_FILE=cert.pfx PFX_PASS=secret ./scripts/sign-windows.sh
#
# Optional: TIMESTAMP_URL (default DigiCert's), PUBLISHER_URL (company site
# embedded in the signature).
set -euo pipefail
cd "$(dirname "$0")/.."

TIMESTAMP_URL="${TIMESTAMP_URL:-http://timestamp.digicert.com}"
PUBLISHER_URL="${PUBLISHER_URL:-}"

if [ "$#" -eq 0 ]; then
  set -- dist/privacylens-windows-*.exe dist/privacylens-gui-windows-*.exe
fi

if [ -n "${JSIGN_ARGS:-}" ]; then
  command -v jsign >/dev/null || { echo "jsign not found: brew install jsign"; exit 1; }
  for exe in "$@"; do
    [ -e "$exe" ] || { echo "not found: $exe — run scripts/build-all.sh first"; exit 1; }
    echo "signing $exe"
    # JSIGN_ARGS is deliberately unquoted: it holds several options.
    # shellcheck disable=SC2086
    jsign $JSIGN_ARGS --name "PrivacyLens" ${PUBLISHER_URL:+--url "$PUBLISHER_URL"} \
      --tsaurl "$TIMESTAMP_URL" --tsmode RFC3161 --replace "$exe"
  done
elif [ -n "${PFX_FILE:-}" ]; then
  : "${PFX_PASS:?set PFX_PASS to the certificate password}"
  command -v osslsigncode >/dev/null || { echo "osslsigncode not found: brew install osslsigncode"; exit 1; }
  for exe in "$@"; do
    [ -e "$exe" ] || { echo "not found: $exe — run scripts/build-all.sh first"; exit 1; }
    echo "signing $exe"
    osslsigncode sign \
      -pkcs12 "$PFX_FILE" -pass "$PFX_PASS" \
      -n "PrivacyLens" ${PUBLISHER_URL:+-i "$PUBLISHER_URL"} \
      -t "$TIMESTAMP_URL" \
      -in "$exe" -out "${exe%.exe}-signed.exe"
    osslsigncode verify "${exe%.exe}-signed.exe" || true
    mv "${exe%.exe}-signed.exe" "$exe"
  done
else
  echo "sign-windows.sh: set JSIGN_ARGS (cloud service / token) or PFX_FILE + PFX_PASS (.pfx file); see the comments at the top of this script" >&2
  exit 1
fi

echo "done"
