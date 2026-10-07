#!/usr/bin/env bash
# Builds everything a release needs into dist/:
#
#   dist/privacylens-<os>-<arch>[.exe]      the CLI for every platform
#   dist/privacylens-gui-*, PrivacyLens-*.app   the double-click GUI launcher
#   dist/packages/                          what gets handed to customers:
#       PrivacyLens-Setup-<ver>.exe         Windows setup wizard (x64 + ARM64)
#       PrivacyLens-<ver>.pkg               macOS installer (Apple + Intel)
#       PrivacyLens-<ver>-<os>-<arch>.zip / .tar.gz
#                                           portable packages with
#                                           double-click install scripts
#
# The setup wizard needs makensis (brew install makensis / apt install
# nsis) and the .pkg needs macOS; each is skipped with a note when its tool
# is missing, so the script still works everywhere.
#
# Signing: SIGN=1 plus the variables described in scripts/sign-macos.sh and
# scripts/sign-windows.sh signs the programs before they are packaged and
# the installers after they are built. Without SIGN=1 everything is
# unsigned.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/.*Version = "\(.*\)"/\1/p' internal/buildinfo/buildinfo.go)
echo "version ${VERSION}"
mkdir -p dist
SIGN="${SIGN:-0}"
ICON_DIR="$PWD/packaging/icon"
GUIDE="$PWD/docs/PrivacyLens-User-Guide.docx"

# winres <cmd-dir> <original-filename>: generate the Windows resource
# objects (icon, version info, manifest) that `go build` links into the
# .exe. Without them the program still works; it just has no icon and an
# empty Properties > Details tab.
winres() {
  local tmp
  tmp=$(mktemp -d)
  cp "${ICON_DIR}/icon-256.png" "$tmp/icon.png" # go-winres resolves paths beside the json
  sed -e "s|@ICON@|icon.png|" -e "s|@DESC@|PrivacyLens|g" \
      -e "s|@FILE@|$2|g" -e "s|@VERSION@|${VERSION}|g" \
      packaging/windows/winres.json > "$tmp/winres.json"
  rm -f "$1"/rsrc_windows_*.syso
  if ! go run github.com/tc-hib/go-winres@v0.3.3 make --in "$tmp/winres.json" \
        --out "$1/rsrc" --arch amd64,arm64 \
        --product-version "${VERSION}.0" --file-version "${VERSION}.0"; then
    echo "note: could not generate Windows resources for $1; building without icon/version info"
  fi
  rm -rf "$tmp"
}
winres cmd/privacylens privacylens.exe
winres cmd/privacylens-gui privacylens-gui.exe

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

# make_app <dir.app> <executable>: assemble a macOS .app bundle around an
# already-built launcher. A bare executable opens a Terminal window when
# double-clicked in Finder; a bundle does not.
make_app() {
  local app=$1 exe=$2
  rm -rf "$app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  sed "s/@VERSION@/${VERSION}/g" scripts/macos-Info.plist > "$app/Contents/Info.plist"
  cp "${ICON_DIR}/icon.icns" "$app/Contents/Resources/icon.icns"
  cp "$exe" "$app/Contents/MacOS/PrivacyLens"
  chmod 755 "$app/Contents/MacOS/PrivacyLens"
}

build_app() {
  local goarch=$1
  local app="dist/PrivacyLens-${goarch}.app"
  echo "building ${app}"
  local tmp
  tmp=$(mktemp -d)
  CGO_ENABLED=0 GOOS=darwin GOARCH="$goarch" \
    go build -trimpath -ldflags="-s -w" -o "$tmp/PrivacyLens" ./cmd/privacylens-gui
  make_app "$app" "$tmp/PrivacyLens"
  rm -rf "$tmp"
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

# Sign the programs first, so every package below carries signed files.
if [ "$SIGN" = "1" ]; then
  [ -n "${SIGN_IDENTITY:-}" ] && ./scripts/sign-macos.sh programs
  ./scripts/sign-windows.sh dist/privacylens-windows-*.exe dist/privacylens-gui-windows-*.exe
elif [ "$(uname)" = "Darwin" ]; then
  # No Developer ID: seal the Mac programs with an ad-hoc signature. The Go
  # linker already ad-hoc signs the arm64 executables, but not the Intel
  # ones and not the .app bundle as a whole, and a downloaded bundle whose
  # seal does not verify is what macOS reports as "damaged and can't be
  # opened". Sealed, it gets the ordinary "unidentified developer" dialog,
  # which System Settings > Privacy & Security > Open Anyway clears. Only
  # notarization (SIGN=1 with a Developer ID) removes the dialog entirely.
  for app in dist/PrivacyLens-*.app; do
    codesign --force --deep --sign - --identifier com.cybx.privacylens.gui "$app"
    codesign --verify --deep --strict "$app"
  done
  for bin in dist/privacylens-darwin-*; do
    codesign --force --sign - --identifier com.cybx.privacylens "$bin"
  done
  echo "ad-hoc signed the macOS programs (unsigned release: expect the unidentified-developer dialog on download)"
fi

PKG=dist/packages
rm -rf "$PKG"
mkdir -p "$PKG"

# ---- Portable packages -----------------------------------------------------
# One archive per platform holding the program under its plain name, the GUI
# launcher, double-click install/uninstall scripts, and a short READ ME —
# see packaging/. These need no installer tooling and work on every target.

# stage <package-name> <packaging-subdir>: start a package folder from the
# templates, stamping the version into its read-me.
stage() {
  local dir="$PKG/$1"
  mkdir -p "$dir"
  find packaging/"$2" -maxdepth 1 -type f \( -name '*.cmd' -o -name '*.command' -o -name '*.sh' -o -name '*.txt' \) -exec cp -p {} "$dir"/ \;
  cp "$GUIDE" "$dir/PrivacyLens User Guide.docx"
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
  if [ -e "dist/privacylens-gui-linux-${arch}" ]; then
    cp "dist/privacylens-gui-linux-${arch}" "$dir/privacylens-gui"
  fi
  tar -czf "$PKG/${name}.tar.gz" -C "$PKG" "$name"
  rm -rf "$dir"
done

# ---- Windows setup wizard ---------------------------------------------------
# One Setup.exe for both CPU types; see packaging/windows/installer.nsi.
if command -v makensis >/dev/null; then
  setup="$PKG/PrivacyLens-Setup-${VERSION}.exe"
  echo "building ${setup}"
  tmp=$(mktemp -d)
  for arch in amd64 arm64; do
    mkdir -p "$tmp/$arch"
    cp "dist/privacylens-windows-${arch}.exe" "$tmp/$arch/privacylens.exe"
    cp "dist/privacylens-gui-windows-${arch}.exe" "$tmp/$arch/privacylens-gui.exe"
  done
  # makensis on macOS crashes (std::bad_alloc) under the C locale; any UTF-8
  # locale avoids it.
  nsis_lc="${LC_ALL:-}"
  if [ "$(uname)" = "Darwin" ]; then nsis_lc=en_US.UTF-8; fi
  LC_ALL="$nsis_lc" makensis -V2 \
    -DVERSION="$VERSION" -DSRC_AMD64="$tmp/amd64" -DSRC_ARM64="$tmp/arm64" \
    -DGUIDE="$GUIDE" -DICON="${ICON_DIR}/icon.ico" -DOUTFILE="$PWD/$setup" \
    packaging/windows/installer.nsi
  rm -rf "$tmp"
  [ "$SIGN" = "1" ] && ./scripts/sign-windows.sh "$setup"
else
  echo "note: makensis not found - skipping the Windows setup wizard (brew install makensis / apt install nsis)"
fi

# ---- macOS installer package -------------------------------------------------
# A universal (Apple Silicon + Intel) .pkg that installs the CLI and the app
# and then runs "privacylens install"; see packaging/macos/pkg/.
if [ "$(uname)" = "Darwin" ] && command -v pkgbuild >/dev/null && [ -x /usr/bin/lipo ]; then
  pkg="$PKG/PrivacyLens-${VERSION}.pkg"
  echo "building ${pkg}"
  tmp=$(mktemp -d)
  root="$tmp/root"
  mkdir -p "$root/usr/local/bin" "$root/Applications"
  /usr/bin/lipo -create dist/privacylens-darwin-arm64 dist/privacylens-darwin-amd64 \
    -output "$root/usr/local/bin/privacylens"
  chmod 755 "$root/usr/local/bin/privacylens"
  /usr/bin/lipo -create "dist/PrivacyLens-arm64.app/Contents/MacOS/PrivacyLens" \
    "dist/PrivacyLens-amd64.app/Contents/MacOS/PrivacyLens" -output "$tmp/PrivacyLens"
  make_app "$root/Applications/PrivacyLens.app" "$tmp/PrivacyLens"
  if [ "$SIGN" = "1" ] && [ -n "${SIGN_IDENTITY:-}" ]; then
    # lipo produced new files, so they are signed here rather than reusing
    # the per-architecture signatures.
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$root/usr/local/bin/privacylens"
    codesign --force --deep --options runtime --timestamp --sign "$SIGN_IDENTITY" "$root/Applications/PrivacyLens.app"
  else
    # Same ad-hoc seal as the per-architecture programs above; without it
    # the installed bundle fails verification ("invalid resource directory").
    codesign --force --sign - --identifier com.cybx.privacylens "$root/usr/local/bin/privacylens"
    codesign --force --deep --sign - --identifier com.cybx.privacylens.gui "$root/Applications/PrivacyLens.app"
    codesign --verify --deep --strict "$root/Applications/PrivacyLens.app"
  fi

  # Installer would otherwise "relocate" the app onto any other copy of the
  # same bundle it finds on the disk (a build folder, a Downloads copy)
  # instead of putting it in /Applications.
  pkgbuild --analyze --root "$root" "$tmp/components.plist" >/dev/null
  /usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$tmp/components.plist" 2>/dev/null ||
    /usr/libexec/PlistBuddy -c "Add :0:BundleIsRelocatable bool false" "$tmp/components.plist"
  # Always replace an existing copy, including when reinstalling the same
  # or an older version.
  /usr/libexec/PlistBuddy -c "Set :0:BundleIsVersionChecked false" "$tmp/components.plist"

  mkdir -p "$tmp/scripts" "$tmp/resources"
  cp packaging/macos/pkg/postinstall "$tmp/scripts/postinstall"
  chmod 755 "$tmp/scripts/postinstall"
  for f in welcome.html conclusion.html; do
    sed "s/@VERSION@/${VERSION}/g" "packaging/macos/pkg/$f" > "$tmp/resources/$f"
  done
  # (pkgbuild prints "write: Permission denied" once per provenance-tagged
  # file; that is the condition handled just below, not a failure.)
  pkgbuild --quiet --root "$root" --component-plist "$tmp/components.plist" \
    --identifier com.cybx.privacylens.pkg --version "$VERSION" \
    --scripts "$tmp/scripts" --ownership recommended --install-location / \
    "$tmp/PrivacyLens-component.pkg" 2> >(grep -v '^write: Permission denied$' >&2 || true)
  # Files created under some apps (third-party terminals, editors, agents)
  # carry a com.apple.provenance attribute that cannot be removed, and
  # pkgbuild turns each one into an empty "._name" entry that would be
  # installed as a junk file. When that happened, rebuild the payload and
  # its bill of materials without them.
  if pkgutil --payload-files "$tmp/PrivacyLens-component.pkg" | grep -q '/\._'; then
    pkgutil --expand "$tmp/PrivacyLens-component.pkg" "$tmp/expanded"
    (cd "$root" && find . -print | sort | COPYFILE_DISABLE=1 cpio -o --format odc -R 0:0 2>/dev/null | gzip -c) > "$tmp/expanded/Payload"
    lsbom "$tmp/expanded/Bom" | grep -v '/\._' > "$tmp/bom.txt"
    mkbom -i "$tmp/bom.txt" "$tmp/expanded/Bom"
    sed -i '' "s/numberOfFiles=\"[0-9]*\"/numberOfFiles=\"$(wc -l < "$tmp/bom.txt" | tr -d ' ')\"/" "$tmp/expanded/PackageInfo"
    rm "$tmp/PrivacyLens-component.pkg"
    pkgutil --flatten "$tmp/expanded" "$tmp/PrivacyLens-component.pkg"
    if pkgutil --payload-files "$tmp/PrivacyLens-component.pkg" | grep -q '/\._'; then
      echo "error: could not strip ._ entries from the package payload" >&2
      exit 1
    fi
  fi
  sed "s/@VERSION@/${VERSION}/g" packaging/macos/pkg/distribution.xml > "$tmp/distribution.xml"
  productbuild --quiet --distribution "$tmp/distribution.xml" \
    --package-path "$tmp" --resources "$tmp/resources" "$pkg"
  rm -rf "$tmp"
  if [ "$SIGN" = "1" ] && [ -n "${INSTALLER_IDENTITY:-}" ]; then
    ./scripts/sign-macos.sh pkg "$pkg"
  fi
else
  echo "note: not on macOS - skipping the .pkg installer"
fi

echo
echo "Done. Binaries in dist/, customer-ready packages in ${PKG}/:"
ls -lh "$PKG"
