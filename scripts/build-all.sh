#!/usr/bin/env bash
# Builds release binaries for every supported platform into dist/:
# the privacylens CLI, and the privacylens-gui double-click launcher
# (a windowed .exe on Windows, a PrivacyLens.app bundle on macOS).
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/.*Version = "\(.*\)"/\1/p' internal/buildinfo/buildinfo.go)
echo "version ${VERSION}"
mkdir -p dist

build() {
  local goos=$1 goarch=$2 suffix=$3
  local out="dist/privacylens-${goos}-${goarch}${suffix}"
  echo "building ${out}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags="-s -w" -o "$out" ./cmd/privacylens
}

# build_gui: the one-click launcher. On Windows -H=windowsgui makes it a
# windowed executable — double-click opens the browser GUI with no console
# window. Startup errors surface in a native dialog instead.
build_gui() {
  local goos=$1 goarch=$2 suffix=$3
  local ldflags="-s -w"
  [ "$goos" = "windows" ] && ldflags="-s -w -H=windowsgui"
  local out="dist/privacylens-gui-${goos}-${goarch}${suffix}"
  echo "building ${out}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags="$ldflags" -o "$out" ./cmd/privacylens-gui
}

# build_app: macOS double-click means an .app bundle — a bare executable
# opens a Terminal window when double-clicked in Finder.
build_app() {
  local goarch=$1
  local app="dist/PrivacyLens-${goarch}.app"
  echo "building ${app}"
  rm -rf "$app"
  mkdir -p "$app/Contents/MacOS"
  sed "s/@VERSION@/${VERSION}/g" scripts/macos-Info.plist > "$app/Contents/Info.plist"
  CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" \
    go build -trimpath -ldflags="-s -w" -o "$app/Contents/MacOS/PrivacyLens" ./cmd/privacylens-gui
}

build darwin  arm64 ""
build darwin  amd64 ""
build linux   amd64 ""
build linux   arm64 ""
build windows amd64 ".exe"
build windows arm64 ".exe"

# 32-bit ARM (appliances). Outlook mail scanning is stubbed out on this
# target — go-pst's io_uring dependency needs 64-bit (see extract/mail_stub.go).
echo "building dist/privacylens-linux-armv7"
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
  go build -trimpath -ldflags="-s -w" -o dist/privacylens-linux-armv7 ./cmd/privacylens

build_gui windows amd64 ".exe"
build_gui windows arm64 ".exe"
build_gui linux   amd64 ""
build_app arm64
build_app amd64

echo
echo "Done. Binaries in dist/:"
ls -lh dist/

# Optional signing: set SIGN=1 (plus the env vars each script needs) to sign
# in the same run. See scripts/sign-macos.sh and scripts/sign-windows.sh.
if [ "${SIGN:-0}" = "1" ]; then
  [ -n "${SIGN_IDENTITY:-}" ] && ./scripts/sign-macos.sh
  [ -n "${PFX_FILE:-}" ] && ./scripts/sign-windows.sh
fi
