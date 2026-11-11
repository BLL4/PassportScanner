import AppKit
import MRTDKit
import SwiftUI

// Only one instance may talk to the reader at a time: two apps polling the same PC/SC
// reader interrupt each other's sessions. Info.plist also sets LSMultipleInstancesProhibited,
// but that is not honoured when the binary is launched directly, so check here as well.
if let bundleID = Bundle.main.bundleIdentifier {
    let others = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
        .filter { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }
    if let existing = others.first {
        existing.activate()
        exit(0)
    }
}
if !ReaderLock.acquire() {
    let alert = NSAlert()
    alert.messageText = "Another reader program is running"
    alert.informativeText = "Passport Scanner or mrtd-read is already using the NFC reader. Only one program can use it at a time."
    alert.runModal()
    exit(0)
}

PassportScannerApp.main()
