import AppKit
import MRTDKit
import SwiftUI

struct ResultPanel: View {
    @EnvironmentObject var model: AppModel
    @State private var showLog = false

    var body: some View {
        VStack(spacing: 0) {
            if model.documentKind == .license {
                if let dl = model.license {
                    ScrollView { LicenseView(license: dl).padding() }
                } else {
                    VStack(spacing: 12) {
                        Image(systemName: "barcode.viewfinder").font(.system(size: 64)).foregroundStyle(.tertiary)
                        Text("No license scanned yet").font(.title3).foregroundStyle(.secondary)
                        Text("Scan the PDF417 barcode on the back of a US or Canadian driver's license or state ID.")
                            .font(.callout).foregroundStyle(.tertiary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else if let data = model.result {
                ScrollView {
                    PassportView(data: data).padding()
                }
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "person.text.rectangle")
                        .font(.system(size: 64)).foregroundStyle(.tertiary)
                    Text(model.isReading ? model.step : "No document read yet")
                        .font(.title3).foregroundStyle(.secondary)
                    Text("Passports and ICAO-compliant ID cards (e.g. EU ID cards issued since 2021) are supported.")
                        .font(.callout).foregroundStyle(.tertiary)
                    PlacementTips()
                        .padding(.top, 12)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            Divider()
            HStack {
                Button(showLog ? "Hide Log" : "Show Log") { showLog.toggle() }
                Spacer()
                if model.documentKind == .license, let dl = model.license {
                    Button { Exporter.export(dl) } label: { Label("Export…", systemImage: "square.and.arrow.up") }
                    Button("Clear") { model.clear() }
                } else if model.documentKind == .chip, let r = model.result {
                    Button { Exporter.export(r) } label: { Label("Export…", systemImage: "square.and.arrow.up") }
                    Button("Clear") { model.clear() }
                }
            }
            .padding(8)
            if showLog {
                ScrollView {
                    Text(model.log.joined(separator: "\n"))
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
                .frame(height: 180)
                .background(.background.secondary)
            }
        }
    }
}

struct LicenseView: View {
    let license: DriverLicense

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 4) {
                Text(license.familyName ?? "–").font(.largeTitle.bold()).textSelection(.enabled)
                Text([license.givenNames, license.suffix].compactMap { $0 }.joined(separator: " ")).font(.title2).textSelection(.enabled)
                HStack(spacing: 8) {
                    Text(license.documentType == "ID" ? "Identification card" : "Driver's license")
                    if let st = license.state { Text("· \(st)") }
                    if let real = license.isRealIDCompliant {
                        Label(real ? "REAL ID" : "Not REAL ID", systemImage: real ? "star.circle.fill" : "circle")
                            .foregroundStyle(real ? .orange : .secondary)
                    }
                    if license.isExpired { Text("EXPIRED").bold().foregroundStyle(.red) }
                }
                .foregroundStyle(.secondary)
            }

            GroupBox("Main data") {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 4) {
                    row("License / ID number", license.licenseNumber)
                    row("Date of birth", DriverLicense.format(license.dateOfBirth))
                    row("Sex", license.sex)
                    row("Issued", DriverLicense.format(license.dateOfIssue))
                    row("Expires", DriverLicense.format(license.dateOfExpiry))
                    row("Address", license.address)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            GroupBox("All barcode fields") {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 4) {
                    ForEach(license.order, id: \.self) { code in
                        if let v = license.displayValue(code) {
                            GridRow {
                                Text(DriverLicense.label(code)).foregroundStyle(.secondary)
                                Text(v).textSelection(.enabled)
                                Text(code).font(.caption.monospaced()).foregroundStyle(.tertiary)
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            Label("Read from the barcode (AAMVA version \(license.aamvaVersion), issuer \(license.issuerID)). Barcodes are not digitally signed, so this data cannot be verified as genuine.",
                  systemImage: "info.circle")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder func row(_ label: String, _ value: String?) -> some View {
        if let value {
            GridRow {
                Text(label).foregroundStyle(.secondary)
                Text(value).textSelection(.enabled)
            }
        }
    }
}

/// How to place documents on the reader; shown while no document has been read.
struct PlacementTips: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Placing the document").font(.headline)
            tip("book.closed", "US passports: open the passport and lay the back cover (older passports) or the plastic photo page (newer passports) flat on the reader. The cover is shielded, so a closed passport cannot be read.")
            tip("book", "Other passports: lay the passport flat. If it is not detected, open it and try the front cover, back cover, or photo page.")
            tip("creditcard", "ID cards: lay the card flat in the centre of the reader.")
            tip("hand.raised", "Keep the document still while reading. Remove covers and sleeves, and keep phones and other cards away.")
        }
        .font(.callout)
        .padding(14)
        .frame(maxWidth: 460, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }

    private func tip(_ icon: String, _ text: String) -> some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: icon).foregroundStyle(.secondary).frame(width: 22)
        }
    }
}

struct PassportView: View {
    let data: PassportData

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .top, spacing: 20) {
                FaceView(image: data.faceImage)
                VStack(alignment: .leading, spacing: 6) {
                    if let m = data.mrz {
                        Text("\(m.surname)").font(.largeTitle.bold()).textSelection(.enabled)
                        Text(m.givenNames).font(.title2).textSelection(.enabled)
                        Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 4) {
                            row("Document", "\(documentType(m)) · \(m.documentNumber)")
                            row("Issuing state", m.issuingState)
                            row("Nationality", m.nationality)
                            row("Date of birth", MRZDate.display(m.dateOfBirth, isExpiry: false))
                            row("Sex", m.sex.isEmpty ? "–" : m.sex)
                            row("Date of expiry", MRZDate.display(m.dateOfExpiry, isExpiry: true))
                            if !m.optionalData.isEmpty { row("Optional data", m.optionalData) }
                            if !m.optionalData2.isEmpty { row("Optional data 2", m.optionalData2) }
                        }
                        .padding(.top, 8)
                    } else {
                        Text("DG1 (MRZ) could not be read").foregroundStyle(.red)
                    }
                }
                Spacer()
                if let sig = data.signatureImage, let img = NSImage(data: Data(sig.data)) {
                    VStack {
                        Image(nsImage: img).resizable().scaledToFit().frame(width: 160)
                        Text("Signature").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            if let d = data.personalDetails, !d.items.isEmpty { FieldSection(title: "Additional personal details (DG11)", fields: d) }
            if let d = data.documentDetails, !d.items.isEmpty { FieldSection(title: "Additional document details (DG12)", fields: d) }

            SecuritySection(data: data)

            if let m = data.mrz {
                GroupBox("MRZ from chip") {
                    Text(m.lines.joined(separator: "\n"))
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(4)
                }
            }
        }
    }

    func documentType(_ m: MRZ) -> String {
        switch m.documentCode.prefix(1) {
        case "P": return "Passport"
        case "I", "A", "C": return "Identity card"
        case "V": return "Visa"
        default: return m.documentCode
        }
    }

    @ViewBuilder func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }
}

struct FaceView: View {
    let image: FaceImage?

    var body: some View {
        Group {
            if let image, let ns = NSImage(data: Data(image.data)) {
                Image(nsImage: ns).resizable().scaledToFit()
            } else {
                ZStack {
                    RoundedRectangle(cornerRadius: 6).fill(.quaternary)
                    Image(systemName: "person.crop.rectangle").font(.system(size: 48)).foregroundStyle(.tertiary)
                }
            }
        }
        .frame(width: 180, height: 230)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .contextMenu {
            if let image { Button("Save Photo…") { Exporter.saveImage(image) } }
        }
    }
}

struct FieldSection: View {
    let title: String
    let fields: LabeledFields

    var body: some View {
        GroupBox(title) {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 4) {
                ForEach(Array(fields.items.enumerated()), id: \.offset) { _, f in
                    GridRow {
                        Text(f.label).foregroundStyle(.secondary)
                        Text(f.value).textSelection(.enabled)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
        }
    }
}

struct SecuritySection: View {
    @EnvironmentObject var model: AppModel
    let data: PassportData

    var body: some View {
        GroupBox("Chip security") {
            VStack(alignment: .leading, spacing: 8) {
                status(true, "Access control: \(data.accessControl)")
                if let pa = data.passiveAuth {
                    let hashes = pa.dataGroupHashes.sorted { $0.key < $1.key }
                    status(pa.hashesValid,
                           pa.hashesValid ? "Data integrity: all \(hashes.count) data groups match the signed hashes (\(pa.hashAlgorithm))"
                                          : "Data integrity: hash MISMATCH in " + hashes.filter { !$0.value }.map(\.key.name).joined(separator: ", "))
                    switch pa.signature {
                    case .valid: status(true, "Document signer signature is valid")
                    case .invalid(let why): status(false, "Document signer signature is INVALID: \(why)")
                    case .notChecked(let why): status(nil, "Signature not checked: \(why)")
                    }
                    if let s = pa.signer {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Document signer: \(s.subjectDescription)")
                            Text("Issued by: \(s.issuerDescription)")
                            Text("Key: \(s.keyDescription)" + (s.notAfter.map { " · valid until \($0.formatted(date: .abbreviated, time: .omitted))" } ?? ""))
                        }
                        .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                    switch pa.csca {
                    case .valid:
                        status(true, "Document signer was issued by the country's CSCA: \(pa.cscaCertificate?.subjectDescription ?? "")")
                    case .invalid(let why): status(false, "CSCA check FAILED: \(why)")
                    case .notChecked(let why): status(nil, "CSCA not checked: \(why)")
                    }
                    HStack {
                        Button("Load CSCA Master List…") { model.loadMasterList() }
                        if !model.csca.certificates.isEmpty {
                            Text("\(model.csca.certificates.count) certificates, \(model.csca.countries.count) countries")
                                .font(.caption).foregroundStyle(.secondary)
                            Button("Remove") { model.clearMasterList() }.controlSize(.small)
                        }
                    }
                    if let m = model.cscaMessage { Text(m).font(.caption).foregroundStyle(.secondary) }
                    if pa.csca != .valid {
                        Text("Get a master list from the German BSI (bsi.bund.de, search “CSCA Masterlist”) or the ICAO PKD (download.pkd.icao.int). Only load lists from sources you trust.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else {
                    status(nil, "Passive authentication not performed (EF.SOD not read)")
                }
                Divider()
                Text("Files read: " + data.files.keys.sorted().map { "\($0.name) (\(data.files[$0]!.count) B)" }.joined(separator: ", "))
                    .font(.caption).foregroundStyle(.secondary)
                if !data.restricted.isEmpty {
                    Text("Not readable by design: " + data.restricted.map { "\($0.name) (\($0.title.lowercased()))" }.joined(separator: ", ")
                         + ". These are protected by Extended Access Control and can only be read by authorised government terminals, e.g. at border control.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(data.errors.sorted { $0.key < $1.key }, id: \.key) { dg, e in
                    Text("\(dg.name): \(e)").font(.caption).foregroundStyle(.orange)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
        }
    }

    @ViewBuilder func status(_ ok: Bool?, _ text: String) -> some View {
        Label {
            Text(text).textSelection(.enabled)
        } icon: {
            switch ok {
            case true?: Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
            case false?: Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
            case nil: Image(systemName: "info.circle").foregroundStyle(.secondary)
            }
        }
    }
}

@MainActor
enum Exporter {
    static func export(_ dl: DriverLicense) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = SafeFileName.make([dl.familyName, dl.licenseNumber], fallback: "license") + ".json"
        panel.message = "Contains personal data – store it safely"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        var fields: [String: String] = [:]
        for code in dl.order { if let v = dl.displayValue(code) { fields["\(code) \(DriverLicense.label(code))"] = v } }
        let json: [String: Any] = ["type": dl.documentType, "issuerID": dl.issuerID, "aamvaVersion": dl.aamvaVersion, "fields": fields]
        do {
            try JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys]).write(to: url)
        } catch {
            NSAlert(error: error).runModal()
        }
    }

    static func saveImage(_ image: FaceImage) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = image.format == .jpeg ? "face.jpg" : "face.jp2"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? Data(image.data).write(to: url)
    }

    /// Writes a summary JSON, the photo and the raw chip files into a chosen folder.
    static func export(_ data: PassportData) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Export Here"
        panel.message = "Choose a folder for the exported data (contains personal data – store it safely)"
        guard panel.runModal() == .OK, let base = panel.url else { return }
        // Chip data is untrusted: never use it in a path without sanitizing (e.g. a surname of "../../x").
        let name = SafeFileName.make([data.mrz?.surname, data.mrz?.documentNumber])
        do {
            let dir = try SafeFileName.child(of: base, name)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            var summary: [String: Any] = ["accessControl": data.accessControl]
            if let m = data.mrz {
                summary["mrz"] = m.lines
                summary["documentCode"] = m.documentCode
                summary["issuingState"] = m.issuingState
                summary["documentNumber"] = m.documentNumber
                summary["surname"] = m.surname
                summary["givenNames"] = m.givenNames
                summary["nationality"] = m.nationality
                summary["dateOfBirth"] = MRZDate.display(m.dateOfBirth, isExpiry: false)
                summary["sex"] = m.sex
                summary["dateOfExpiry"] = MRZDate.display(m.dateOfExpiry, isExpiry: true)
            }
            for (key, fields) in [("personalDetails", data.personalDetails), ("documentDetails", data.documentDetails)] {
                if let f = fields { summary[key] = Dictionary(f.items.map { ($0.label, $0.value) }, uniquingKeysWith: { a, _ in a }) }
            }
            if let pa = data.passiveAuth {
                summary["passiveAuthentication"] = [
                    "hashAlgorithm": pa.hashAlgorithm,
                    "dataGroupHashes": Dictionary(uniqueKeysWithValues: pa.dataGroupHashes.map { ($0.key.name, $0.value) }),
                    "signature": "\(pa.signature)",
                    "documentSigner": pa.signer?.subjectDescription ?? "",
                ]
            }
            let json = try JSONSerialization.data(withJSONObject: summary, options: [.prettyPrinted, .sortedKeys])
            try json.write(to: dir.appendingPathComponent("summary.json"))
            if let img = data.faceImage {
                try Data(img.data).write(to: dir.appendingPathComponent(img.format == .jpeg ? "face.jpg" : "face.jp2"))
            }
            let raw = dir.appendingPathComponent("raw")
            try FileManager.default.createDirectory(at: raw, withIntermediateDirectories: true)
            for (dg, bytes) in data.files { try Data(bytes).write(to: raw.appendingPathComponent("\(dg.name).bin")) }
            NSWorkspace.shared.activateFileViewerSelecting([dir])
        } catch {
            let alert = NSAlert(error: error)
            alert.runModal()
        }
    }
}
