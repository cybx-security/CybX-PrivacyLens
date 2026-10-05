#!/usr/bin/env bash
# Signs and notarizes the macOS binaries in dist/ so customer machines run
# them without Gatekeeper warnings.
#
# Prerequisites (one-time):
#   1. Apple Developer Program membership ($99/yr): developer.apple.com
#   2. A "Developer ID Application" certificate installed in your keychain
#      (Xcode > Settings > Accounts > Manage Certificates, or developer portal)
#   3. An app-specific password for notarization: appleid.apple.com >
#      Sign-In & Security > App-Specific Passwords
#   4. Store the notarization credentials once:
#        xcrun notarytool store-credentials privacylens-notary \
#          --apple-id you@example.com --team-id YOURTEAMID
#
# Usage:
#   SIGN_IDENTITY="Developer ID Application: Your Company (TEAMID)" \
#     ./scripts/sign-macos.sh
set -euo pipefail
cd "$(dirname "$0")/.."

: "${SIGN_IDENTITY:?set SIGN_IDENTITY to your Developer ID Application identity}"
KEYCHAIN_PROFILE="${KEYCHAIN_PROFILE:-privacylens-notary}"

for bin in dist/privacylens-darwin-*; do
  [ -e "$bin" ] || { echo "no darwin binaries in dist/ — run scripts/build-all.sh first"; exit 1; }
  echo "signing $bin"
  codesign --force --options runtime --timestamp \
    --sign "$SIGN_IDENTITY" "$bin"
  codesign --verify --strict --verbose=2 "$bin"

  echo "notarizing $bin"
  zip -j "${bin}.zip" "$bin"
  xcrun notarytool submit "${bin}.zip" \
    --keychain-profile "$KEYCHAIN_PROFILE" --wait
  rm "${bin}.zip"
  # Standalone binaries can't be stapled (no bundle); Gatekeeper checks the
  # notarization ticket online on first run instead.
done

# The GUI launcher ships as an .app bundle: sign the bundle, notarize the
# zipped bundle, then staple the ticket so first launch works offline.
for app in dist/PrivacyLens-*.app; do
  [ -e "$app" ] || continue
  echo "signing $app"
  codesign --force --deep --options runtime --timestamp \
    --sign "$SIGN_IDENTITY" "$app"
  codesign --verify --strict --verbose=2 "$app"

  echo "notarizing $app"
  ditto -c -k --keepParent "$app" "${app}.zip"
  xcrun notarytool submit "${app}.zip" \
    --keychain-profile "$KEYCHAIN_PROFILE" --wait
  rm "${app}.zip"
  xcrun stapler staple "$app"
done

echo "done — verify with: spctl -a -vv -t install dist/privacylens-darwin-arm64"
