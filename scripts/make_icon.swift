// Draws the app icon (passport + ID card + NFC waves) and writes Resources/AppIcon.icns.
// Run: swift scripts/make_icon.swift
import AppKit

let size: CGFloat = 1024
func color(_ hex: UInt32, _ a: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: a)
}

func drawIcon(in ctx: CGContext) {
    let s = size
    // Background: macOS-style rounded square with a deep blue gradient.
    let bgRect = CGRect(x: 100, y: 100, width: s - 200, height: s - 200)
    let bg = NSBezierPath(roundedRect: bgRect, xRadius: 185, yRadius: 185)
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 30, color: color(0x000000, 0.35).cgColor)
    color(0x1B3A6B).setFill()
    bg.fill()
    ctx.restoreGState()
    NSGradient(colors: [color(0x2E6FD8), color(0x163070)])!.draw(in: bg, angle: -70)

    // Passport booklet, tilted, behind.
    ctx.saveGState()
    ctx.translateBy(x: 420, y: 560)
    ctx.rotate(by: 0.16)
    let book = CGRect(x: -190, y: -250, width: 380, height: 500)
    ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 24, color: color(0x000000, 0.45).cgColor)
    let bookPath = NSBezierPath(roundedRect: book, xRadius: 26, yRadius: 26)
    color(0x7A1F2B).setFill()
    bookPath.fill()
    ctx.setShadow(offset: .zero, blur: 0, color: nil)
    NSGradient(colors: [color(0x9C2A38), color(0x5E1620)])!.draw(in: bookPath, angle: -60)
    // spine
    color(0x000000, 0.18).setFill()
    NSBezierPath(rect: CGRect(x: -190, y: -250, width: 28, height: 500)).fill()
    // gold emblem
    let gold = color(0xE8C46A)
    gold.setStroke()
    let emblem = NSBezierPath(ovalIn: CGRect(x: -70, y: 10, width: 140, height: 140))
    emblem.lineWidth = 12
    emblem.stroke()
    let inner = NSBezierPath(ovalIn: CGRect(x: -36, y: 44, width: 72, height: 72))
    inner.lineWidth = 9
    inner.stroke()
    // "PASSPORT" bar and chip symbol (the ePassport logo)
    gold.setFill()
    NSBezierPath(roundedRect: CGRect(x: -110, y: -50, width: 220, height: 22), xRadius: 11, yRadius: 11).fill()
    let chip = NSBezierPath(roundedRect: CGRect(x: -48, y: -190, width: 96, height: 62), xRadius: 8, yRadius: 8)
    chip.lineWidth = 9
    chip.stroke()
    let chipDot = NSBezierPath(ovalIn: CGRect(x: -16, y: -175, width: 32, height: 32))
    chipDot.lineWidth = 8
    chipDot.stroke()
    ctx.restoreGState()

    // ID card in front.
    ctx.saveGState()
    ctx.translateBy(x: 560, y: 360)
    ctx.rotate(by: -0.08)
    let card = CGRect(x: -270, y: -170, width: 540, height: 340)
    let cardPath = NSBezierPath(roundedRect: card, xRadius: 34, yRadius: 34)
    ctx.setShadow(offset: CGSize(width: 0, height: -14), blur: 30, color: color(0x000000, 0.5).cgColor)
    color(0xF4F7FB).setFill()
    cardPath.fill()
    ctx.setShadow(offset: .zero, blur: 0, color: nil)
    NSGradient(colors: [color(0xFFFFFF), color(0xDCE6F2)])!.draw(in: cardPath, angle: -90)
    cardPath.addClip()
    // header band
    color(0x2E6FD8).setFill()
    NSBezierPath(rect: CGRect(x: -270, y: 110, width: 540, height: 60)).fill()
    // photo with person silhouette
    let photo = CGRect(x: -235, y: -95, width: 150, height: 185)
    color(0xB9C9DE).setFill()
    NSBezierPath(roundedRect: photo, xRadius: 14, yRadius: 14).fill()
    color(0x5A7499).setFill()
    NSBezierPath(ovalIn: CGRect(x: -192, y: 0, width: 64, height: 64)).fill()
    NSBezierPath(roundedRect: CGRect(x: -222, y: -95, width: 124, height: 95), xRadius: 50, yRadius: 50).fill()
    // text lines
    color(0x8DA2BF).setFill()
    for (i, w) in [230.0, 180, 205].enumerated() {
        NSBezierPath(roundedRect: CGRect(x: -55, y: 60 - Double(i) * 42, width: w, height: 20), xRadius: 10, yRadius: 10).fill()
    }
    // MRZ lines
    color(0x34465E).setFill()
    for row in 0..<2 {
        for col in 0..<17 {
            let x = -235 + Double(col) * 28
            let h: Double = (col * 7 + row * 3) % 5 == 0 ? 6 : 16
            NSBezierPath(rect: CGRect(x: x, y: -150 + Double(row) * 30 + (16 - h) / 2, width: 18, height: h)).fill()
        }
    }
    ctx.restoreGState()

    // NFC waves, top right.
    ctx.saveGState()
    color(0xFFFFFF, 0.95).setStroke()
    let center = CGPoint(x: 700, y: 700)
    for (i, r) in [55.0, 105, 155].enumerated() {
        let arc = NSBezierPath()
        arc.appendArc(withCenter: center, radius: r, startAngle: -10, endAngle: 75)
        arc.lineWidth = 30 - CGFloat(i) * 4
        arc.lineCapStyle = .round
        arc.stroke()
    }
    color(0xFFFFFF).setFill()
    NSBezierPath(ovalIn: CGRect(x: center.x - 20, y: center.y - 20, width: 40, height: 40)).fill()
    ctx.restoreGState()
}

let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size), bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
drawIcon(in: NSGraphicsContext.current!.cgContext)
NSGraphicsContext.restoreGraphicsState()

let root = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ".")
let iconset = FileManager.default.temporaryDirectory.appendingPathComponent("AppIcon.iconset")
try? FileManager.default.removeItem(at: iconset)
try! FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
let master = NSImage(size: NSSize(width: size, height: size))
master.addRepresentation(rep)
for base in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let px = base * scale
        let r = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
                                 hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: r)
        NSGraphicsContext.current!.imageInterpolation = .high
        master.draw(in: NSRect(x: 0, y: 0, width: px, height: px))
        NSGraphicsContext.restoreGraphicsState()
        let name = scale == 1 ? "icon_\(base)x\(base).png" : "icon_\(base)x\(base)@2x.png"
        try! r.representation(using: .png, properties: [:])!.write(to: iconset.appendingPathComponent(name))
    }
}
try! rep.representation(using: .png, properties: [:])!.write(to: root.appendingPathComponent("Resources/AppIcon.png"))
let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", iconset.path, "-o", root.appendingPathComponent("Resources/AppIcon.icns").path]
try! p.run()
p.waitUntilExit()
print("Wrote Resources/AppIcon.icns")
