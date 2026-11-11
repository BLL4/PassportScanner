#!/bin/zsh
# Regenerates docs/screenshot.png: runs the app in demo mode with the fictional ICAO specimen
# document (no reader or real data needed); the app saves a picture of its window and quits.
set -euo pipefail
cd "${0:A:h}/.."
scripts/build.sh >/dev/null
mkdir -p docs
# The app allows only one instance: make sure a running one has quit first.
pkill -f "Passport Scanner.app/Contents/MacOS/PassportScanner" || true
while pgrep -f "Passport Scanner.app/Contents/MacOS/PassportScanner" >/dev/null; do sleep 0.2; done
PASSPORT_SCANNER_SCREENSHOT="$PWD/docs/screenshot.png" "build/Passport Scanner.app/Contents/MacOS/PassportScanner"
echo "Wrote docs/screenshot.png"
