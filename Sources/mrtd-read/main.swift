import Foundation
import ImageIO
import MRTDKit

// Command-line reader, useful for testing readers and chips without the GUI.
let usage = """
usage: mrtd-read --list
       mrtd-read --ocr IMAGE            (MRZ or US driver's license barcode)
       mrtd-read --probe [--reader NAME]
       mrtd-read (--mrz DOCNO,YYMMDD,YYMMDD | --mrz-text "LINE1\\nLINE2" | --can NNNNNN)
                 [--reader NAME] [--out DIR] [--no-image] [--csca MASTERLIST] [--verbose]
"""

var args = Array(CommandLine.arguments.dropFirst())
func value(_ flag: String) -> String? {
    guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
    return args[i + 1]
}
let verbose = args.contains("--verbose")

if args.contains("--list") {
    let names = SmartCardTransport.readerNames
    print(names.isEmpty ? "No readers found" : names.joined(separator: "\n"))
    exit(0)
}

if let path = value("--ocr") {
    // Recognise the MRZ in an image file (no reader needed).
    guard let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil),
          let img = CGImageSourceCreateImageAtIndex(src, 0, nil) else { print("Cannot open \(path)"); exit(1) }
    if let dl = await BarcodeRecognizer.recognize(cgImage: img) {
        print("Driver's license barcode (AAMVA v\(dl.aamvaVersion), IIN \(dl.issuerID)):")
        for code in dl.order { if let v = dl.displayValue(code) { print("  \(DriverLicense.label(code)): \(v)") } }
        exit(0)
    }
    guard let mrz = await MRZTextRecognizer.recognize(cgImage: img) else { print("No valid MRZ or driver's license barcode found"); exit(1) }
    print(mrz.lines.joined(separator: "\n"))
    print("Key: \(mrz.key.documentNumber),\(mrz.key.dateOfBirth),\(mrz.key.dateOfExpiry)  all check digits valid: \(mrz.allValid)")
    exit(0)
}

guard ReaderLock.acquire() else {
    print("Another reader program (Passport Scanner or mrtd-read) is using the NFC reader. Quit it first.")
    exit(1)
}

let probe = args.contains("--probe")
var key: AccessKey?
if let m = value("--mrz") {
    let p = m.split(separator: ",").map(String.init)
    guard p.count == 3 else { print(usage); exit(2) }
    key = .mrz(MRZKey(documentNumber: p[0], dateOfBirth: p[1], dateOfExpiry: p[2]))
} else if let t = value("--mrz-text") {
    do { key = .mrz(try MRZ(t.replacingOccurrences(of: "\\n", with: "\n")).key) } catch { print(error.localizedDescription); exit(2) }
} else if let c = value("--can") {
    key = .can(c)
}
if key == nil && !probe { print(usage); exit(2) }

do {
    let t = try await SmartCardTransport.connect(reader: value("--reader"), timeout: Double(value("--timeout") ?? "30") ?? 30) { print($0) }
    print("Reader: \(t.readerName)\nATR: \(t.atr.hex)")
    if probe {
        let chip = Chip(transport: t) { print($0) }
        let ca = try? await chip.readFile(sfi: 0x1C, name: "EF.CardAccess")
        if let ca {
            print("EF.CardAccess: \(ca.hex)")
            for info in PACEInfo.parse(cardAccess: ca) { print("  \(info) supported=\(info.isSupported)") }
        } else {
            print("No EF.CardAccess: BAC only")
        }
        exit(0)
    }
    let reader = PassportReader(transport: t) { if verbose { print($0) } }
    reader.options.readFaceImage = !args.contains("--no-image")
    if let path = value("--csca") {
        let store = CSCAStore(certificates: CSCAStore.certificates(fromFile: Bytes(try Data(contentsOf: URL(fileURLWithPath: path)))))
        print("CSCA: \(store.certificates.count) certificates from \(store.countries.count) countries")
        reader.options.csca = store
    }
    var lastStep = ""
    let data = try await reader.read(key: key!) { p in
        if p.step != lastStep { lastStep = p.step; print("[\(Int(p.fraction * 100))%] \(p.step)") }
    }
    print("\nAccess control: \(data.accessControl)")
    if let m = data.mrz {
        print("Document: \(m.documentCode) \(m.issuingState) \(m.documentNumber)  (\(m.format.rawValue))")
        print("Name: \(m.surname), \(m.givenNames)")
        print("Nationality: \(m.nationality)  Sex: \(m.sex)")
        print("Born: \(MRZDate.display(m.dateOfBirth, isExpiry: false))  Expires: \(MRZDate.display(m.dateOfExpiry, isExpiry: true))")
    }
    for f in (data.personalDetails?.items ?? []) + (data.documentDetails?.items ?? []) { print("\(f.label): \(f.value)") }
    if let img = data.faceImage { print("Face image: \(img.format.rawValue) \(img.data.count) bytes") }
    if let pa = data.passiveAuth {
        print("Passive auth (\(pa.hashAlgorithm)): " + pa.dataGroupHashes.sorted { $0.key < $1.key }.map { "\($0.key.name)=\($0.value ? "ok" : "MISMATCH")" }.joined(separator: " "))
        print("Signature: \(pa.signature)")
        if let s = pa.signer { print("Signer: \(s.subjectDescription) [\(s.keyDescription)]") }
        print("CSCA: \(pa.csca)" + (pa.cscaCertificate.map { " – \($0.subjectDescription)" } ?? ""))
    }
    for (dg, e) in data.errors.sorted(by: { $0.key < $1.key }) { print("\(dg.name): \(e)") }
    if !data.restricted.isEmpty {
        print("Government-only (Extended Access Control): " + data.restricted.map(\.name).joined(separator: ", "))
    }
    if let dir = value("--out") {
        let url = URL(fileURLWithPath: dir)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        for (dg, bytes) in data.files { try Data(bytes).write(to: url.appendingPathComponent("\(dg.name).bin")) }
        if let img = data.faceImage {
            try Data(img.data).write(to: url.appendingPathComponent(img.format == .jpeg ? "face.jpg" : "face.jp2"))
        }
        print("Saved to \(url.path)")
    }
    t.close()
} catch {
    print("Error: \(error.localizedDescription)")
    exit(1)
}
