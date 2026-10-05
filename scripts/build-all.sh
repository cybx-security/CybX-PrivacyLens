#!/usr/bin/env bash
# Builds release binaries for every supported platform into dist/:
# the privacylens CLI, and the privacylens-gui double-click launcher
# (a windowed .exe on Windows, a PrivacyLens.app bundle on macOS) — then
# assembles the customer-ready install packages in dist/packages/.
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

# Optional signing: set SIGN=1 (plus the env vars each script needs) to sign
# in the same run. See scripts/sign-macos.sh and scripts/sign-windows.sh.
# Signing happens before packaging so the packages carry the signed files.
if [ "${SIGN:-0}" = "1" ]; then
  [ -n "${SIGN_IDENTITY:-}" ] && ./scripts/sign-macos.sh
  [ -n "${PFX_FILE:-}" ] && ./scripts/sign-windows.sh
fi

# Release packages: what actually gets handed to a customer. Each one is a
# single download holding the program under its plain name, the GUI
# launcher, double-click install/uninstall scripts, and a short
# plain-language READ ME — see packaging/.
PKG=dist/packages
rm -rf "$PKG"
mkdir -p "$PKG"

# stage <package-name> <packaging-subdir>: start a package folder from the
# templates, stamping the version into its read-me.
stage() {
  local dir="$PKG/$1"
  mkdir -p "$dir"
  cp -p packaging/"$2"/* "$dir"/
  cp docs/PrivacyLens-User-Guide.docx "$dir/PrivacyLens User Guide.docx"
  for f in "$dir"/*.txt; do
    sed "s/@VERSION@/${VERSION}/g" "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  done
  echo "$dir"
}

for arch in amd64 arm64; do
  name="PrivacyLens-${VERSION}-windows-${arch}"
  dir=$(stage "$name" windows)
  cp dist/privacylens-windows-${arch}.exe "$dir/privacylens.exe"
  cp dist/privacylens-gui-windows-${arch}.exe "$dir/privacylens-gui.exe"
  (cd "$PKG" && zip -qr "${name}.zip" "$name")
  rm -rf "$dir"

  name="PrivacyLens-${VERSION}-macos-${arch}"
  dir=$(stage "$name" macos)
  cp dist/privacylens-darwin-${arch} "$dir/privacylens"
  cp -R "dist/PrivacyLens-${arch}.app" "$dir/PrivacyLens.app"
  (cd "$PKG" && zip -qry "${name}.zip" "$name")
  rm -rf "$dir"
done

for arch in amd64 arm64 armv7; do
  name="PrivacyLens-${VERSION}-linux-${arch}"
  dir=$(stage "$name" linux)
  cp dist/privacylens-linux-${arch} "$dir/privacylens"
  # The GUI launcher is only built for amd64; elsewhere "privacylens gui"
  # does the same job from a terminal.
  [ -e "dist/privacylens-gui-linux-${arch}" ] && cp "dist/privacylens-gui-linux-${arch}" "$dir/privacylens-gui"
  tar -czf "$PKG/${name}.tar.gz" -C "$PKG" "$name"
  rm -rf "$dir"
done

echo
echo "Done. Binaries in dist/, customer-ready packages in ${PKG}/:"
ls -lh dist/ "$PKG"
