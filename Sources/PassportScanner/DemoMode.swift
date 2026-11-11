import AppKit
import MRTDKit

/// Fills the window with the fictional ICAO 9303 specimen document and saves a picture of the window.
/// Used only to produce the README screenshot: `scripts/screenshot.sh` (PASSPORT_SCANNER_SCREENSHOT=path).
/// No chip, reader or real personal data is involved.
@MainActor
enum DemoMode {
    static var outputPath: String? { ProcessInfo.processInfo.environment["PASSPORT_SCANNER_SCREENSHOT"] }

    static func run(model: AppModel) {
        guard let path = outputPath else { return }
        NSApp.appearance = NSAppearance(named: .aqua)
        let mrz = try! MRZ("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10")
        model.apply(mrz)

        var data = PassportData()
        data.accessControl = "PACE (ECDH-GM AES-128 brainpoolP256r1)"
        data.mrz = mrz
        data.faceImage = FaceImage(data: placeholderPortrait(), format: .jpeg, width: 360, height: 460)
        data.personalDetails = LabeledFields(items: [
            ("Full name", "ERIKSSON, ANNA MARIA"), ("Place of birth", "ZENITH, UTOPIA"), ("Full date of birth", "1974-08-12"),
        ])
        data.documentDetails = LabeledFields(items: [("Issuing authority", "UTOPIA PASSPORT OFFICE"), ("Date of issue", "2002-04-16")])
        data.files = [.com: Bytes(repeating: 0, count: 26), .dg1: Bytes(repeating: 0, count: 93), .dg2: Bytes(repeating: 0, count: 15_843),
                      .dg11: Bytes(repeating: 0, count: 58), .dg12: Bytes(repeating: 0, count: 47), .sod: Bytes(repeating: 0, count: 1_912)]
        data.passiveAuth = PassiveAuthResult(hashAlgorithm: "SHA-256", dataGroupHashes: [.dg1: true, .dg2: true, .dg11: true, .dg12: true],
                                             dataGroupsInSOD: [.dg1, .dg2, .dg11, .dg12], signature: .valid, signer: nil)
        data.restricted = [.dg3]
        model.result = data
        model.step = "Done – you can remove the document"

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            guard let window = NSApp.windows.first(where: { $0.isVisible }) else { exit(1) }
            window.setContentSize(NSSize(width: 1180, height: 760))
            window.center()
            window.makeFirstResponder(nil) // no focus ring / text selection in the picture
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                // The window's own content can be captured without screen recording permission.
                guard let view = window.contentView, let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { exit(1) }
                view.cacheDisplay(in: view.bounds, to: rep)
                try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
                exit(0)
            }
        }
    }

    /// A drawn silhouette standing in for the face photo.
    static func placeholderPortrait() -> Bytes {
        let w = 360, h = 460
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: w, pixelsHigh: h, bitsPerSample: 8, samplesPerPixel: 4,
                                   hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
        NSGradient(colors: [NSColor(white: 0.93, alpha: 1), NSColor(srgbRed: 0.80, green: 0.85, blue: 0.92, alpha: 1)])!
            .draw(in: NSRect(x: 0, y: 0, width: w, height: h), angle: -90)
        NSColor(srgbRed: 0.36, green: 0.45, blue: 0.60, alpha: 1).setFill()
        NSBezierPath(ovalIn: NSRect(x: 115, y: 220, width: 130, height: 160)).fill()
        NSBezierPath(roundedRect: NSRect(x: 45, y: -60, width: 270, height: 270), xRadius: 120, yRadius: 120).fill()
        NSGraphicsContext.restoreGraphicsState()
        return Bytes(rep.representation(using: .jpeg, properties: [.compressionFactor: 0.9])!)
    }
}
