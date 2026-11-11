import MRTDKit
import SwiftUI
import UniformTypeIdentifiers

struct PassportScannerApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        Window("Passport Scanner", id: "main") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 960, minHeight: 640)
        }
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Passport Scanner") { AboutPanel.show() }
            }
        }
    }
}

enum AboutPanel {
    static func show() {
        let text = """
        Passport Scanner reads the NFC chip of electronic passports and ID cards \
        (ICAO 9303 documents, such as European ID cards) with a USB smart card reader.

        To unlock the chip, enter the MRZ data (scan it with the camera or a photo, or type it) \
        or, on ID cards, the 6-digit Card Access Number (CAN) printed on the front.

        The app shows the holder's data and photo, and checks that the data was signed by the \
        issuing country (passive authentication; load a CSCA master list for the full check).

        It can also read the PDF417 barcode on US and Canadian driver's licenses and ID cards \
        (camera or photo).

        Read-only: nothing is ever written to the chip. All data stays on this Mac.
        """
        let style = NSMutableParagraphStyle()
        style.alignment = .center
        let credits = NSAttributedString(string: text, attributes: [
            .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
            .foregroundColor: NSColor.labelColor,
            .paragraphStyle: style,
        ])
        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationName: "Passport Scanner",
            .credits: credits,
            NSApplication.AboutPanelOptionKey(rawValue: "Copyright"): "Scans passports and ID cards via NFC",
        ])
        NSApp.activate()
    }
}

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    @State private var dropTargeted = false

    var body: some View {
        HSplitView {
            AccessPanel()
                .frame(minWidth: 330, idealWidth: 350, maxWidth: 420)
            ResultPanel()
                .frame(minWidth: 520, maxWidth: .infinity, maxHeight: .infinity)
        }
        .sheet(isPresented: $model.showCamera) {
            if model.documentKind == .license {
                CameraSheet(mode: .barcode, onFound: { _ in }, onLicense: { model.apply($0) })
            } else {
                CameraSheet(mode: .mrz, onFound: { model.apply($0) })
            }
        }
        .onAppear { DemoMode.run(model: model) }
        .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
            guard let p = providers.first else { return false }
            _ = p.loadObject(ofClass: URL.self) { url, _ in
                if let url { Task { @MainActor in model.scanImage(at: url) } }
            }
            return true
        }
        .overlay {
            if dropTargeted {
                RoundedRectangle(cornerRadius: 12).strokeBorder(Color.accentColor, lineWidth: 3).padding(4)
            }
        }
    }
}

struct AccessPanel: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        ScrollView {
            content.padding()
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Passport Scanner", systemImage: "person.text.rectangle")
                .font(.title2.bold())

            Picker("", selection: $model.documentKind) {
                Text("Passport / ID (chip)").tag(DocumentKind.chip)
                Text("US driver's license").tag(DocumentKind.license)
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            if model.documentKind == .license {
                LicenseScanPanel()
            } else {
            GroupBox("1 · Access key") {
                VStack(alignment: .leading, spacing: 10) {
                    Picker("", selection: $model.accessMode) {
                        Text("MRZ (passport / ID)").tag(AccessMode.mrz)
                        Text("CAN (ID card)").tag(AccessMode.can)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()

                    if model.accessMode == .mrz {
                        HStack {
                            Button { model.showCamera = true } label: { Label("Camera", systemImage: "camera.viewfinder") }
                            Button { model.scanImageFile() } label: { Label("Open Image…", systemImage: "photo") }
                        }
                        Text("…or drop a photo of the data page here, or type. ID card? The CAN tab is often easier.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        LabeledField("Document number", text: $model.documentNumber, prompt: "e.g. L898902C3")
                        LabeledField("Date of birth", text: $model.dateOfBirth, prompt: "YYMMDD")
                        LabeledField("Date of expiry", text: $model.dateOfExpiry, prompt: "YYMMDD")
                        if let m = model.scannedMRZ {
                            Text(m.lines.joined(separator: "\n"))
                                .font(.system(size: 9, design: .monospaced))
                                .textSelection(.enabled)
                                .padding(6)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
                            if !m.keyFieldsValid {
                                Label("Check digit wrong for: " + failedChecks(m).joined(separator: ", ") + ". Correct the fields or scan again.",
                                      systemImage: "exclamationmark.triangle")
                                    .font(.caption).foregroundStyle(.red)
                            } else if !m.compositeValid {
                                Label("The final (composite) check digit did not match, probably a misread character outside the fields above. The key fields are valid, so reading the chip should work; the chip's own MRZ is shown after reading.",
                                      systemImage: "info.circle")
                                    .font(.caption).foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    } else {
                        LabeledField("Card Access Number", text: $model.can, prompt: "6 digits")
                        Text("The Card Access Number (CAN) is a 6-digit number printed on the front of most European ID cards (and some newer passports), often in the bottom-right corner. It unlocks the chip just like the MRZ, without any scanning.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let e = model.keyError {
                        Text(e).font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(4)
            }

            GroupBox("2 · Reader") {
                VStack(alignment: .leading, spacing: 8) {
                    if model.readers.isEmpty {
                        Label("No NFC reader found. Connect a USB PC/SC contactless reader (e.g. ACR122U, ACR1252U).",
                              systemImage: "exclamationmark.triangle")
                            .font(.callout).foregroundStyle(.orange)
                    } else {
                        Picker("Reader", selection: $model.selectedReader) {
                            ForEach(model.readers, id: \.self) { Text($0).tag(Optional($0)) }
                        }
                        .labelsHidden()
                    }
                    Toggle("Read face image (slower)", isOn: $model.readFaceImage)
                }
                .padding(4)
            }

            GroupBox("3 · Read") {
                VStack(alignment: .leading, spacing: 8) {
                    if model.isReading {
                        ProgressView(value: model.progress)
                        HStack {
                            Text(model.step).font(.callout).lineLimit(2)
                            Spacer()
                            Button("Cancel") { model.cancel() }
                        }
                    } else {
                        Button {
                            model.read()
                        } label: {
                            Label("Read Chip", systemImage: "wave.3.right").frame(maxWidth: .infinity)
                        }
                        .controlSize(.large)
                        .buttonStyle(.borderedProminent)
                        .disabled(!model.canRead)
                        .keyboardShortcut(.defaultAction)
                        Text("Place the document flat on the reader and keep it still while reading.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        if !model.step.isEmpty { Text(model.step).font(.callout).foregroundStyle(.green) }
                    }
                    if let e = model.errorMessage {
                        Text(e).font(.callout).foregroundStyle(.red).textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(4)
            }

            }

            Text("Read-only: this app never writes to the chip. All data stays on this Mac.")
                .font(.caption2).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct LicenseScanPanel: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        GroupBox("Scan the barcode") {
            VStack(alignment: .leading, spacing: 10) {
                Text("US and Canadian driver's licenses and state ID cards have no chip. Their data is in the PDF417 barcode on the back.")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button { model.showCamera = true } label: { Label("Camera", systemImage: "barcode.viewfinder") }
                    Button { model.scanImageFile() } label: { Label("Open Image…", systemImage: "photo") }
                }
                Text("…or drop a photo of the back of the card here. A sharp, well-lit photo works best.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Label("The barcode is not digitally signed, so unlike a passport chip its data cannot be verified as genuine.",
                      systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let e = model.errorMessage {
                    Text(e).font(.callout).foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(4)
        }
    }
}

func failedChecks(_ m: MRZ) -> [String] {
    [(m.documentNumberValid, "document number"), (m.dateOfBirthValid, "date of birth"), (m.dateOfExpiryValid, "date of expiry")]
        .filter { !$0.0 }.map(\.1)
}

struct LabeledField: View {
    let label: String
    @Binding var text: String
    let prompt: String

    init(_ label: String, text: Binding<String>, prompt: String) {
        self.label = label
        _text = text
        self.prompt = prompt
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            TextField(prompt, text: $text)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))
                .onChange(of: text) { _, new in
                    let up = new.uppercased().filter { !$0.isWhitespace }
                    if up != new { text = up }
                }
        }
    }
}
