#!/bin/zsh
# Builds build/Passport Scanner.app and build/mrtd-read, ad-hoc signed with the smart card entitlement.
set -euo pipefail
cd "${0:A:h}/.."
swift build -c release --product PassportScanner
swift build -c release --product mrtd-read
BIN=$(swift build -c release --show-bin-path)
APP="build/Passport Scanner.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/PassportScanner" "$APP/Contents/MacOS/"
cp Resources/Info.plist "$APP/Contents/"
[[ -f Resources/AppIcon.icns ]] && cp Resources/AppIcon.icns "$APP/Contents/Resources/"
codesign --force --sign - --entitlements Resources/PassportScanner.entitlements "$APP"
cp "$BIN/mrtd-read" build/mrtd-read
codesign --force --sign - --entitlements Resources/PassportScanner.entitlements build/mrtd-read
echo "Built: $APP and build/mrtd-read"
