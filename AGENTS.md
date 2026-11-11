# Privacy and security review

This repository is a macOS app (Passport Scanner) and CLI (`mrtd-read`) that read passports, ID cards
and US driver's licenses. These contain highly sensitive personal data: names, dates of birth,
document numbers, addresses and face photos. Your task is to verify that this data cannot leak and
that the app cannot harm the documents. Review all of `Sources/`, `Tests/`, `scripts/`, `Resources/`
and `Package.swift`. Report findings; do not change code unless asked.

## Checks

1. **No network access.**
   - Search for URLSession, URLRequest, NWConnection / Network framework, CFNetwork, sockets,
     WKWebView, `NSWorkspace.open` with URLs, `Process` launching tools such as curl.
   - `Package.swift` must have no external dependencies; build scripts must not download anything.
   - Entitlements must not include `com.apple.security.network.client` or `.server`.
2. **No automatic storage of personal data.**
   - List every file write, UserDefaults / @AppStorage, Keychain, Core Data / SwiftData and cache use,
     and confirm each one either stores no personal data or runs only after an explicit user action
     (e.g. a Save/Export panel).
   - Expected exceptions: CSCA certificates (public data, stored only when the user loads a master list)
     and the empty reader lock file.
   - Camera frames, images and OCR results must stay in memory only.
3. **Exports only on explicit request.** Exported file names built from document data must be
   sanitized, and writes must stay inside the folder the user chose.
4. **Logs and error messages contain no personal data.** Check `print`, NSLog, os_log/Logger, the
   in-app log view and error texts. The APDU log must not show decrypted chip contents.
5. **No clipboard or sharing without a user action** (no automatic NSPasteboard writes, no share
   extensions).
6. **The chip is never written to.** All APDUs must go through `Chip.send`, whose allowlist must contain
   only read and authentication instructions (A4, B0, B1, 84, 82, 22, 86, C0). Confirm no other code
   calls `transmit`, and that no write commands (D6, D0, DA, DC, E0, E4, 0E, 44 …) can be sent.
7. **Camera** is active only while the scan sheet is open, and is processed on-device only.
8. **Untrusted input is handled safely.** Chip data, barcodes, image files and master lists are
   attacker-controlled. Check parsers for crashes (out-of-range indexing), unbounded memory use and
   path traversal.
9. **No real personal data in the repository.** Tests and fixtures must use only ICAO specimen or
   synthetic data: no real MRZs, photos, chip dumps, logs or crash reports.
10. **Nothing suspicious:** obfuscated strings, unexplained base64 blobs, hidden URLs, timers or
    background tasks, downloaded code being executed, or entitlements beyond smart card, camera and
    user-selected files.

## Report format

For each check: **PASS / FAIL / NEEDS ATTENTION**, with `file:line` evidence. List real problems
separately from hardening suggestions.

