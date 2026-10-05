#!/usr/bin/env bash
# Signs and notarizes the macOS deliverables so customer Macs open them
# without Gatekeeper warnings. scripts/build-all.sh calls this when SIGN=1.
#
#   ./scripts/sign-macos.sh programs      sign + notarize the CLI binaries and
#                                         .app bundles in dist/ (the default)
#   ./scripts/sign-macos.sh pkg <file>    sign + notarize + staple an
#                                         installer package
#
# One-time setup (see README, "Code signing"):
#   1. Apple Developer Program membership ($99/yr), enrolled as the company.
#   2. Two certificates in this Mac's keychain, both created by the account
#      holder at developer.apple.com > Certificates:
#        "Developer ID Application: <Company> (<TEAMID>)"  - signs programs
#        "Developer ID Installer: <Company> (<TEAMID>)"    - signs .pkg files
#   3. Notarization credentials stored once:
#        xcrun notarytool store-credentials privacylens-notary \
#          --apple-id you@example.com --team-id YOURTEAMID
#      (it asks for an app-specific password from account.apple.com)
#
# Environment:
#   SIGN_IDENTITY        "Developer ID Application: ..."  (programs)
#   INSTALLER_IDENTITY   "Developer ID Installer: ..."    (pkg)
#   KEYCHAIN_PROFILE     notarytool profile name (default privacylens-notary)
set -euo pipefail
cd "$(dirname "$0")/.."
KEYCHAIN_PROFILE="${KEYCHAIN_PROFILE:-privacylens-notary}"
mode="${1:-programs}"

case "$mode" in
programs)
  : "${SIGN_IDENTITY:?set SIGN_IDENTITY to your Developer ID Application identity}"
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
  ;;

pkg)
  pkg="${2:?usage: sign-macos.sh pkg <file.pkg>}"
  : "${INSTALLER_IDENTITY:?set INSTALLER_IDENTITY to your Developer ID Installer identity}"
  echo "signing $pkg"
  productsign --timestamp --sign "$INSTALLER_IDENTITY" "$pkg" "${pkg}.signed"
  mv "${pkg}.signed" "$pkg"
  pkgutil --check-signature "$pkg"

  # Notarizing the package covers the programs inside it; stapling lets it
  # install on a Mac with no internet connection.
  echo "notarizing $pkg"
  xcrun notarytool submit "$pkg" --keychain-profile "$KEYCHAIN_PROFILE" --wait
  xcrun stapler staple "$pkg"
  echo "done — verify with: spctl -a -vv -t install \"$pkg\""
  ;;

*)
  echo "usage: sign-macos.sh [programs | pkg <file.pkg>]" >&2
  exit 2
  ;;
esac
